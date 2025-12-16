use iced::{
    Application, Command, Element, Settings, Color,
    widget::{Column, Row, Text, Button, TextInput, Container, Scrollable, Space},
    Length, Size, Alignment,
};
use std::fs;
use sysinfo::{System, ProcessRefreshKind};

#[cfg(target_os = "windows")]
use {
    winapi::um::processthreadsapi::OpenProcess,
    winapi::um::memoryapi::{VirtualQueryEx, ReadProcessMemory},
    winapi::um::winnt::{PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_READONLY, PAGE_READWRITE},
    winapi::um::handleapi::CloseHandle,
};

pub fn main() -> iced::Result {
    App::run(Settings {
        window: iced::window::Settings {
            resizable: true,
            size: Size::new(1200.0, 700.0),
            ..Default::default()
        },
        ..Default::default()
    })
}

#[derive(Clone, Debug, PartialEq)]
enum ValueType {
    Byte,
    Int16,
    Int32,
    Int64,
    Float,
    Double,
    String,
}

impl Default for ValueType {
    fn default() -> Self {
        ValueType::Int32
    }
}

impl ValueType {
    fn as_str(&self) -> &str {
        match self {
            ValueType::Byte => "Byte",
            ValueType::Int16 => "2-Byte",
            ValueType::Int32 => "4-Byte (Int32)",
            ValueType::Int64 => "8-Byte (Int64)",
            ValueType::Float => "Float",
            ValueType::Double => "Double",
            ValueType::String => "String",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum ScanType {
    ExactValue,
    GreaterThan,
    LessThan,
    Between,
    Unknown,
    Increased,
    Decreased,
}

impl Default for ScanType {
    fn default() -> Self {
        ScanType::ExactValue
    }
}

impl ScanType {
    fn as_str(&self) -> &str {
        match self {
            ScanType::ExactValue => "Exact Value",
            ScanType::GreaterThan => "Greater Than",
            ScanType::LessThan => "Less Than",
            ScanType::Between => "Between",
            ScanType::Unknown => "Unknown Initial Value",
            ScanType::Increased => "Increased",
            ScanType::Decreased => "Decreased",
        }
    }
}

#[derive(Clone, Debug)]
struct ScanResult {
    address: String,
    value: String,
}

#[derive(Default)]
struct App {
    dark_mode: bool,
    show_process_modal: bool,
    show_settings_modal: bool,
    // Process management
    selected_process: Option<ProcessInfo>,
    system: System,
    search_process: String,
    // Memory scanner
    scan_value: String,
    scan_type: ScanType,
    value_type: ValueType,
    scan_results: Vec<ScanResult>,
    // Async scanning state
    is_scanning: bool,
    scan_progress: String,
    // Selected result for writing
    selected_result_index: Option<usize>,
    write_value: String,
}

#[derive(Clone, Debug)]
struct ProcessInfo {
    name: String,
    pid: u32,
    #[allow(dead_code)]
    memory: u64,
}

#[derive(Debug, Clone)]
enum Message {
    ShowProcessModal,
    HideProcessModal,
    ShowSettingsModal,
    HideSettingsModal,
    ProcessSearchChanged(String),
    SelectProcess(ProcessInfo),
    ScanValueChanged(String),
    ValueTypeChanged(ValueType),
    ScanTypeChanged(ScanType),
    ExecuteScan,
    SelectResult(usize),
    WriteValueChanged(String),
    WriteMemory,
    ScanProgress(String),
    ToggleDarkMode,
}

impl Application for App {
    type Executor = iced::executor::Default;
    type Message = Message;
    type Theme = iced::Theme;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        let app = Self {
            dark_mode: load_config(),
            system: System::new_all(),
            ..Default::default()
        };
        (app, Command::none())
    }

    fn title(&self) -> String {
        "Cereb".into()
    }

    fn theme(&self) -> Self::Theme {
        if self.dark_mode {
            iced::Theme::Dark
        } else {
            iced::Theme::Light
        }
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::ShowProcessModal => {
                self.show_process_modal = true;
                self.system.refresh_processes_specifics(ProcessRefreshKind::new());
            }
            Message::HideProcessModal => {
                self.show_process_modal = false;
            }
            Message::ShowSettingsModal => {
                self.show_settings_modal = true;
            }
            Message::HideSettingsModal => {
                self.show_settings_modal = false;
            }
            Message::SelectProcess(process) => {
                self.selected_process = Some(process);
                self.show_process_modal = false;
                self.search_process.clear();
            }
            Message::ProcessSearchChanged(val) => {
                self.search_process = val;
            }
            Message::ScanValueChanged(val) => {
                self.scan_value = val;
            }
            Message::ValueTypeChanged(vtype) => {
                self.value_type = vtype;
            }
            Message::ScanTypeChanged(stype) => {
                self.scan_type = stype;
            }
            Message::ExecuteScan => {
                if !self.scan_value.is_empty() && self.selected_process.is_some() {
                    self.is_scanning = true;
                    self.scan_progress = "Scanning...".to_string();
                    self.scan_results.clear();
                    
                    // Direct synchronous scan (faster than async for CPU-bound work)
                    let process = self.selected_process.as_ref().unwrap();
                    match self.scan_value.parse::<i32>() {
                        Ok(search_value) => {
                            self.scan_results = scan_process_memory(
                                process.pid,
                                search_value,
                                &self.scan_type,
                                &self.value_type,
                            );
                        }
                        Err(_) => {
                            self.scan_results = vec![ScanResult {
                                address: "ERROR".to_string(),
                                value: "Invalid value format".to_string(),
                            }];
                        }
                    }
                    
                    self.is_scanning = false;
                    self.scan_progress = format!("Found {} results", self.scan_results.len());
                }
            }
            Message::SelectResult(index) => {
                self.selected_result_index = Some(index);
                if let Some(result) = self.scan_results.get(index) {
                    // Pre-populate write value with current value
                    self.write_value = result.value.clone();
                }
            }
            Message::WriteValueChanged(val) => {
                self.write_value = val;
            }

            Message::WriteMemory => {
                if let (Some(process), Some(idx)) = (&self.selected_process, self.selected_result_index) {
                    if let Some(result) = self.scan_results.get(idx) {
                        // Parse address and write value
                        if let Ok(addr) = usize::from_str_radix(result.address.trim_start_matches("0x"), 16) {
                            if let Ok(value) = self.write_value.parse::<i32>() {
                                write_process_memory(process.pid, addr, value);
                                self.scan_progress = format!("Wrote value to 0x{:X}", addr);
                            } else {
                                self.scan_progress = "Invalid value format".to_string();
                            }
                        } else {
                            self.scan_progress = "Invalid address format".to_string();
                        }
                    }
                }
            }
            Message::ScanProgress(_progress) => {}
            Message::ToggleDarkMode => {
                self.dark_mode = !self.dark_mode;
                save_config(self.dark_mode);
            }
        }
        Command::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let menu_bar = Container::new(
            Row::new()
                .push(Text::new("cereb - search and rewrite memory").size(20))
                .push(Space::with_width(Length::Fill))
                .push(Button::new(Text::new("Show Apps")).on_press(Message::ShowProcessModal).padding(10))
                .push(Button::new(Text::new("Settings")).on_press(Message::ShowSettingsModal).padding(10))
                .padding(10)
                .align_items(Alignment::Center)
        )
        .width(Length::Fill)
        .padding(5);

        let process_display = if let Some(process) = &self.selected_process {
            Text::new(format!("Current Process: {} (PID: {})", process.name, process.pid)).size(14)
        } else {
            Text::new("No process selected").size(14)
        };

        let left_panel = Container::new(
            Column::new()
                .push(process_display)
                .push(Text::new("").height(Length::Fixed(20.0)))
                .push(Text::new("Address List").size(16))
                .push(Scrollable::new(
                    Column::new()
                        .push(Text::new("[No addresses yet]").size(12))
                        .spacing(5)
                )
                .height(Length::Fill))
                .spacing(10)
                .padding(15)
        )
        .width(Length::Fixed(350.0))
        .height(Length::Fill);

        let right_panel = Container::new(
            Column::new()
                .push(Text::new("Value Scanner").size(16))
                .push(Text::new("").height(Length::Fixed(10.0)))
                // Value Input
                .push(Text::new("Value:").size(12))
                .push(
                    TextInput::new("Enter value to search...", &self.scan_value)
                        .on_input(Message::ScanValueChanged)
                        .padding(10)
                        .size(12)
                )
                // Value Type Selection
                .push(Text::new("").height(Length::Fixed(8.0)))
                .push(Text::new("Value Type:").size(12))
                .push(
                    Row::new()
                        .push(
                            Button::new(
                                Text::new(if self.value_type == ValueType::Byte { "✓ Byte" } else { "Byte" }).size(10)
                            )
                            .on_press(Message::ValueTypeChanged(ValueType::Byte))
                            .padding(8)
                            .width(Length::Fill)
                        )
                        .push(
                            Button::new(
                                Text::new(if self.value_type == ValueType::Int32 { "✓ 4-Byte" } else { "4-Byte" }).size(10)
                            )
                            .on_press(Message::ValueTypeChanged(ValueType::Int32))
                            .padding(8)
                            .width(Length::Fill)
                        )
                        .spacing(5)
                )
                .push(
                    Row::new()
                        .push(
                            Button::new(
                                Text::new(if self.value_type == ValueType::Float { "✓ Float" } else { "Float" }).size(10)
                            )
                            .on_press(Message::ValueTypeChanged(ValueType::Float))
                            .padding(8)
                            .width(Length::Fill)
                        )
                        .push(
                            Button::new(
                                Text::new(if self.value_type == ValueType::Double { "✓ Double" } else { "Double" }).size(10)
                            )
                            .on_press(Message::ValueTypeChanged(ValueType::Double))
                            .padding(8)
                            .width(Length::Fill)
                        )
                        .spacing(5)
                )
                // Scan Type Selection
                .push(Text::new("").height(Length::Fixed(8.0)))
                .push(Text::new("Scan Type:").size(12))
                .push(
                    Row::new()
                        .push(
                            Button::new(
                                Text::new(if self.scan_type == ScanType::ExactValue { "✓ Exact" } else { "Exact" }).size(10)
                            )
                            .on_press(Message::ScanTypeChanged(ScanType::ExactValue))
                            .padding(8)
                            .width(Length::Fill)
                        )
                        .push(
                            Button::new(
                                Text::new(if self.scan_type == ScanType::GreaterThan { "✓ >" } else { ">" }).size(10)
                            )
                            .on_press(Message::ScanTypeChanged(ScanType::GreaterThan))
                            .padding(8)
                            .width(Length::Fill)
                        )
                        .push(
                            Button::new(
                                Text::new(if self.scan_type == ScanType::LessThan { "✓ <" } else { "<" }).size(10)
                            )
                            .on_press(Message::ScanTypeChanged(ScanType::LessThan))
                            .padding(8)
                            .width(Length::Fill)
                        )
                        .spacing(5)
                )
                // Scan Button
                .push(Text::new("").height(Length::Fixed(10.0)))
                .push({
                    let scan_button = Button::new(
                        Text::new(if self.is_scanning { "Scanning..." } else { "Scan" })
                    )
                    .padding(12)
                    .width(Length::Fill);
                    
                    if self.is_scanning {
                        Row::new().push(scan_button)
                    } else {
                        Row::new().push(scan_button.on_press(Message::ExecuteScan))
                    }
                })
                .push(
                    if !self.scan_progress.is_empty() {
                        Text::new(&self.scan_progress).size(11)
                    } else {
                        Text::new("")
                    }
                )
                // Results
                .push(Text::new("").height(Length::Fixed(10.0)))
                .push(Text::new("Results:").size(13))
                .push(
                    if self.is_scanning {
                        Scrollable::new(
                            Column::new().push(Text::new("Scanning...").size(11))
                        ).height(Length::Fill)
                    } else if self.scan_results.is_empty() {
                        Scrollable::new(
                            Column::new().push(Text::new("No results").size(11))
                        ).height(Length::Fill)
                    } else {
                        Scrollable::new(
                            self.scan_results.iter().enumerate().fold(
                                Column::new().spacing(3),
                                |col, (idx, result)| {
                                    let is_selected = self.selected_result_index == Some(idx);
                                    let bg_color = if is_selected { 
                                        Color::from_rgb(0.2, 0.3, 0.5) 
                                    } else { 
                                        Color::from_rgb(0.1, 0.1, 0.1) 
                                    };
                                    
                                    col.push(
                                        Button::new(
                                            Row::new()
                                                .push(Text::new(&result.address).size(10).width(Length::Fixed(90.0)))
                                                .push(Text::new(&result.value).size(10))
                                                .spacing(10)
                                                .padding(8)
                                        )
                                        .on_press(Message::SelectResult(idx))
                                        .width(Length::Fill)
                                    )
                                }
                            )
                        ).height(Length::Fill)
                    }
                )
                // Write
                .push(Text::new("").height(Length::Fixed(10.0)))
                .push(Text::new("Write Value:").size(12))
                .push(
                    TextInput::new("New value...", &self.write_value)
                        .on_input(Message::WriteValueChanged)
                        .padding(10)
                        .size(12)
                )
                .push({
                    let write_btn = Button::new(Text::new("Write"))
                        .padding(10)
                        .width(Length::Fill);
                    
                    if self.selected_result_index.is_some() && !self.write_value.is_empty() {
                        write_btn.on_press(Message::WriteMemory)
                    } else {
                        write_btn
                    }
                })
                .spacing(8)
                .padding(15)
        )
        .width(Length::Fill)
        .height(Length::Fill);

        let main_content = Row::new()
            .push(left_panel)
            .push(right_panel)
            .height(Length::Fill)
            .spacing(5);

        let base_content = Column::new()
            .push(menu_bar)
            .push(main_content)
            .width(Length::Fill)
            .height(Length::Fill);

        // Main screen
        if !self.show_process_modal && !self.show_settings_modal {
            return base_content.into();
        }

        // Process modal
        if self.show_process_modal {
            let processes: Vec<ProcessInfo> = self.system.processes()
                .iter()
                .map(|(pid, proc)| ProcessInfo {
                    name: proc.name().to_string(),
                    pid: pid.as_u32(),
                    memory: proc.memory(),
                })
                .collect();

            // Filter processes
            let filtered_processes: Vec<ProcessInfo> = if self.search_process.is_empty() {
                processes
            } else {
                let search_lower = self.search_process.to_lowercase();
                processes.into_iter().filter(|p| {
                    p.name.to_lowercase().contains(&search_lower) || 
                    p.pid.to_string().contains(&self.search_process)
                }).collect()
            };

            let process_buttons = filtered_processes.into_iter().map(|p| {
                Button::new(
                    Text::new(format!("{} (PID: {})", p.name, p.pid)).size(12)
                )
                .on_press(Message::SelectProcess(p))
                .width(Length::Fill)
                .padding(10)
            }).fold(
                Column::new().spacing(5),
                |col, btn| col.push(btn)
            );

            let modal_content = Column::new()
                .push(Text::new("Running Applications").size(18))
                .push(Text::new("").height(Length::Fixed(10.0)))
                .push(
                    TextInput::new("Search by name or PID...", &self.search_process)
                        .on_input(Message::ProcessSearchChanged)
                        .padding(10)
                        .size(12)
                )
                .push(Text::new("").height(Length::Fixed(10.0)))
                .push(Scrollable::new(process_buttons).height(Length::Fill))
                .push(Text::new("").height(Length::Fixed(10.0)))
                .push(Button::new(Text::new("Close")).on_press(Message::HideProcessModal).padding(10).width(Length::Fill))
                .spacing(10)
                .padding(20);

            let modal = Container::new(modal_content)
                .width(Length::Fixed(450.0))
                .height(Length::Fixed(550.0));

            Column::new()
                .push(
                    Container::new(
                        Column::new()
                            .push(base_content)
                    )
                    .width(Length::Fill)
                    .height(Length::Fill)
                )
                .push(
                    Container::new(
                        Container::new(modal)
                            .width(Length::Fill)
                            .height(Length::Fill)
                            .center_x()
                            .center_y()
                    )
                    .width(Length::Fill)
                    .height(Length::Fixed(600.0))
                )
                .width(Length::Fill)
                .height(Length::Fill)
                .into()
        } else if self.show_settings_modal {
            let modal_content = Column::new()
                .push(Text::new("Settings").size(20))
                .push(Text::new("").height(Length::Fixed(20.0)))
                .push(
                    Row::new()
                        .push(Text::new("Dark Mode").size(14))
                        .push(Space::with_width(Length::Fill))
                        .push(
                            if self.dark_mode {
                                Text::new("ON").size(13)
                            } else {
                                Text::new("OFF").size(13)
                            }
                        )
                        .spacing(10)
                )
                .push(Button::new(Text::new("Toggle Dark Mode")).on_press(Message::ToggleDarkMode).padding(10).width(Length::Fill))
                .push(Text::new("").height(Length::Fixed(20.0)))
                .push(Button::new(Text::new("Close")).on_press(Message::HideSettingsModal).padding(10).width(Length::Fill))
                .spacing(10)
                .padding(20);

            let modal = Container::new(modal_content)
                .width(Length::Fixed(350.0))
                .height(Length::Fixed(280.0));

            Column::new()
                .push(
                    Container::new(
                        Column::new()
                            .push(base_content)
                    )
                    .width(Length::Fill)
                    .height(Length::Fill)
                )
                .push(
                    Container::new(
                        Container::new(modal)
                            .width(Length::Fill)
                            .height(Length::Fill)
                            .center_x()
                            .center_y()
                    )
                    .width(Length::Fill)
                    .height(Length::Fixed(330.0))
                )
                .width(Length::Fill)
                .height(Length::Fill)
                .into()
        } else {
            base_content.into()
        }
    }
}

impl App {
    fn generate_scan_results(&self) -> Vec<ScanResult> {
        vec![]
    }
}

const CONFIG_FILE: &str = "config.toml";

fn load_config() -> bool {
    fs::read_to_string(CONFIG_FILE)
        .ok()
        .and_then(|content| {
            content.lines().find(|line| line.starts_with("dark_mode")).and_then(|line| {
                line.split('=').nth(1).map(|v| v.trim() == "true")
            })
        })
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn scan_process_memory(pid: u32, search_value: i32, scan_type: &ScanType, value_type: &ValueType) -> Vec<ScanResult> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
        if process_handle.is_null() {
            return vec![ScanResult {
                address: "ERROR".to_string(),
                value: "Cannot open process".to_string(),
            }];
        }

        let mut results = Vec::new();
        let mut current_address: usize = 0;
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let mut found_count = 0;
        const MAX_RESULTS: usize = 100;
        const BUFFER_SIZE: usize = 65536; // 64KB buffer
        const PAGE_SIZE: usize = 4096; // Windows page size
        let mut buffer: Vec<u8> = vec![0; BUFFER_SIZE];

        // Iterate through memory regions
        while VirtualQueryEx(
            process_handle,
            current_address as *const _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) != 0
        {
            let is_readwrite = (mbi.Protect & PAGE_READWRITE) != 0;
            let is_readonly = (mbi.Protect & PAGE_READONLY) != 0;
            
            // Only scan committed, readable memory
            if mbi.State == MEM_COMMIT && (is_readwrite || is_readonly) {
                let region_start = mbi.BaseAddress as usize;
                let region_size = mbi.RegionSize;
                let region_end = region_start + region_size;

                let mut addr = (region_start / PAGE_SIZE) * PAGE_SIZE;
                
                while addr < region_end && found_count < MAX_RESULTS {
                    let bytes_to_read = ((region_end - addr).min(BUFFER_SIZE)).min(region_size);
                    let mut bytes_read: usize = 0;

                    // Try to read, but skip on failure
                    let result = ReadProcessMemory(
                        process_handle,
                        addr as *const _,
                        buffer.as_mut_ptr() as *mut _,
                        bytes_to_read,
                        &mut bytes_read,
                    );

                    if result != 0 && bytes_read >= 4 {
                        let value_size = get_value_type_size(value_type);
                        let step = value_size.max(1);
                        
                        // Search buffer for matching values
                        let mut offset = 0;
                        while offset + value_size <= bytes_read && found_count < MAX_RESULTS {
                            if let Ok(value) = read_value_from_buffer(&buffer, offset, value_type) {
                                let matched = match scan_type {
                                    ScanType::ExactValue => value as i32 == search_value,
                                    ScanType::GreaterThan => (value as i32) > search_value,
                                    ScanType::LessThan => (value as i32) < search_value,
                                    ScanType::Between => {
                                        (value as i32) >= search_value && (value as i32) <= search_value + 100
                                    }
                                    _ => false,
                                };

                                if matched {
                                    results.push(ScanResult {
                                        address: format!("0x{:X}", addr + offset),
                                        value: value.to_string(),
                                    });
                                    found_count += 1;

                                    if found_count >= MAX_RESULTS {
                                        break;
                                    }
                                }
                            }
                            offset += step;
                        }
                    }

                    addr += bytes_to_read.max(PAGE_SIZE);
                }
            }

            current_address += mbi.RegionSize;
        }

        CloseHandle(process_handle);

        if results.is_empty() {
            // results.push(ScanResult {
            //     address: "NO_MATCH".to_string(),
            //     value: "No values found".to_string(),
            // });
        }

        results
    }
}
#[cfg(target_os = "windows")]
fn write_process_memory(pid: u32, address: usize, value: i32) {
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::memoryapi::WriteProcessMemory;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::winnt::{PROCESS_VM_WRITE, PROCESS_VM_OPERATION};
    use winapi::um::errhandlingapi::GetLastError;

    unsafe {
        // Open the process with both write and operation access
        let process_handle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, pid);
        if process_handle.is_null() {
            eprintln!("Failed to open process: {}", GetLastError());
            return;
        }

        let mut bytes_written: usize = 0;
        let result = WriteProcessMemory(
            process_handle,
            address as *mut _,
            &value as *const i32 as *const _,
            std::mem::size_of::<i32>(),
            &mut bytes_written,
        );

        // Check if WriteProcessMemory succeeded
        if result == 0 {
            eprintln!("Failed to write memory: {}", GetLastError());
        } else if bytes_written != std::mem::size_of::<i32>() {
            eprintln!("Partial write: only {} bytes written", bytes_written);
        } else {
            println!("Successfully wrote value: {}", value);
        }

        CloseHandle(process_handle);
    }
}

#[cfg(not(target_os = "windows"))]
fn write_process_memory(_pid: u32, _address: usize, _value: i32) {
    // Not supported on non-Windows
}

#[cfg(not(target_os = "windows"))]
fn scan_process_memory(_pid: u32, _search_value: i32, _scan_type: &ScanType, _value_type: &ValueType) -> Vec<ScanResult> {
    vec![ScanResult {
        address: "NOT_SUPPORTED".to_string(),
        value: "Real memory scanning only available on Windows".to_string(),
    }]
}

fn get_value_type_size(value_type: &ValueType) -> usize {
    match value_type {
        ValueType::Byte => 1,
        ValueType::Int16 => 2,
        ValueType::Int32 => 4,
        ValueType::Int64 => 8,
        ValueType::Float => 4,
        ValueType::Double => 8,
        ValueType::String => 1,
    }
}

fn read_value_from_buffer(buffer: &[u8], offset: usize, value_type: &ValueType) -> Result<u64, String> {
    match value_type {
        ValueType::Byte => {
            if offset < buffer.len() {
                Ok(buffer[offset] as u64)
            } else {
                Err("Out of bounds".to_string())
            }
        }
        ValueType::Int16 => {
            if offset + 1 < buffer.len() {
                let bytes = &buffer[offset..offset + 2];
                Ok(i16::from_le_bytes([bytes[0], bytes[1]]) as u64)
            } else {
                Err("Out of bounds".to_string())
            }
        }
        ValueType::Int32 => {
            if offset + 3 < buffer.len() {
                let bytes = &buffer[offset..offset + 4];
                Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
            } else {
                Err("Out of bounds".to_string())
            }
        }
        ValueType::Int64 => {
            if offset + 7 < buffer.len() {
                let bytes = &buffer[offset..offset + 8];
                Ok(i64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]) as u64)
            } else {
                Err("Out of bounds".to_string())
            }
        }
        ValueType::Float => {
            if offset + 3 < buffer.len() {
                let bytes = &buffer[offset..offset + 4];
                let float = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Ok(float as u64)
            } else {
                Err("Out of bounds".to_string())
            }
        }
        ValueType::Double => {
            if offset + 7 < buffer.len() {
                let bytes = &buffer[offset..offset + 8];
                let double = f64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                Ok(double as u64)
            } else {
                Err("Out of bounds".to_string())
            }
        }
        ValueType::String => Err("String search not yet implemented".to_string()),
    }
}

fn save_config(dark_mode: bool) {
    let content = format!("# App Configuration\ndark_mode = {}\n", dark_mode);
    let _ = fs::write(CONFIG_FILE, content);
}
