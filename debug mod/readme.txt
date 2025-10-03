

  Debugging dvb-gse on VSCode

This guide explains how to set up and debug the   dvb-gse   project in VSCode, including creating a TUN interface, installing dependencies, and configuring the IDE.

---

   1. Creating a TUN Interface

Before running the program, you need to create a TUN interface and grant access to your user:

 bash
sudo ip tuntap add dev tun0 mode tun user $USER
sudo ip link set tun0 up
 

  Note:   After every system reboot, you need to recreate the TUN interface.
If you want the TUN interface to persist across reboots, there are several methods:

---

    1.1 Using `systemd` to Automatically Create TUN

You can create a simple `systemd` service that creates the TUN interface after boot.

1. Create the service file:

 bash
sudo nano /etc/systemd/system/tun0.service
 

2. File contents:

 ini
[Unit]
Description=Create TUN0 interface
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/ip tuntap add dev tun0 mode tun user your_username
ExecStartPost=/sbin/ip link set tun0 up
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
 

  Note: Replace `your_username` with your actual username.

3. Enable the service:

 bash
sudo systemctl daemon-reload
sudo systemctl enable tun0.service
sudo systemctl start tun0.service
 

Now the TUN interface will be automatically created after every system reboot.

---

    1.2 Adding to Boot Script (`/etc/rc.local`)

If your system supports `rc.local`, you can place the TUN commands there:

 bash
sudo nano /etc/rc.local
 

Add before `exit 0`:

 bash
ip tuntap add dev tun0 mode tun user your_username
ip link set tun0 up
 

---

    1.3 Using Network Configuration Files (`/etc/network/interfaces`) – Debian/Ubuntu Only

You can define a persistent TUN interface:

 ini
auto tun0
iface tun0 inet manual
    pre-up ip tuntap add dev tun0 mode tun user your_username
    up ip link set tun0 up
    down ip link set tun0 down
    post-down ip tuntap del dev tun0 mode tun
 

  Among these methods,   systemd   is the most modern and reliable approach, recommended for modern servers.

---

   2. Removing TUN

To delete the TUN interface at any time:

 bash
sudo ip link delete tun0
 

  If you want it to persist after reboot, place the creation commands in a   systemd service   or   boot script  .

---

   3. Installing Required Tools and Libraries

To compile and debug the project, ensure the following tools are installed:

  Rust and Cargo  

 bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update
 

  Build Essentials  

 bash
sudo apt update
sudo apt install build-essential
 

  Libraries  

 bash
sudo apt install libssl-dev
 

  Debugging Tools  

 bash
sudo apt install lldb
sudo apt install gdb
 

---

   4. VSCode Extensions

For a better Rust development and debugging experience in VSCode, install the following extensions from the marketplace:

    Rust Analyzer   for code completion, type hints, and error checking
    CodeLLDB   for debugging Rust with LLDB
    C/C++   for LLDB integration
    Crates   (optional) for managing Cargo dependencies
    Error Lens   (optional) for inline warnings and errors

To install, press `Ctrl+Shift+X` in VSCode, search for the extension, and click Install.

---

   5. Configuring Debugging in VSCode

1. Open the project folder in VSCode.
2. Create a `.vscode` folder in the project root if it does not exist:

 bash
mkdir -p .vscode
 

3. Create a `launch.json` file inside `.vscode`.
     Note:   This file should point to your project binary and include the correct arguments and working directory.

---

   6. Build and Run

  Build the project in debug mode:  

 bash
cargo build
 

  Ensure the TUN interface exists (see step 1).
  Launch the VSCode debugger by pressing F5 and selecting   Debug dvb-gse  .

---

   7. Notes

  For debugging high-speed network code, it’s better to use logging or `println!` instead of breakpoints:

 rust
println!("Packet received: {:?}", packet);
 

  You can also use `env_logger` for configurable logging:

 bash
RUST_LOG=debug cargo run
 

  Always check that the TUN interface exists before running or debugging the program.

  The `launch.json` file should be placed inside the `.vscode` folder in the project root.

---

If you want, I can also prepare this as a   ready-to-use README.md   file for direct use in your project.
