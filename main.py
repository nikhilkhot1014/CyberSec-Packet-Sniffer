import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import sniff, ARP, Ether, IP, TCP, UDP
from collections import defaultdict
import threading


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberSec Packet Sniffer")
        self.root.geometry("1600x900")  # Larger window dimensions
        self.root.configure(bg="#0a0a0a")  # Dark hacker-style background

        self.sniffing = False
        self.arp_table = defaultdict(set)

        # Set up hacker theme
        self.setup_theme()

        # GUI Layout
        self.setup_ui()

    def setup_theme(self):
        """
        Configure custom ttk styles for a hacker-style look.
        """
        style = ttk.Style()
        style.theme_use("clam")

        # Define styles for buttons
        style.configure(
            "Hacker.TButton",
            font=("Consolas", 12, "bold"),
            background="#1f1f1f",  # Dark gray background for buttons
            foreground="#00ff00",  # Neon green text
            borderwidth=2,
            relief="ridge"
        )
        style.map(
            "Hacker.TButton",
            background=[("active", "#00ff00")],
            foreground=[("active", "#000000")]
        )

        # Define styles for labels
        style.configure(
            "Hacker.TLabel",
            background="#0a0a0a",  # Matches background
            foreground="#00ff00",  # Neon green text
            font=("Consolas", 12)
        )

        # Define styles for Treeview
        style.configure(
            "Hacker.Treeview",
            background="#1f1f1f",  # Dark gray
            foreground="#00ff00",  # Neon green text
            fieldbackground="#1f1f1f",  # Matches background
            font=("Consolas", 10)
        )
        style.configure(
            "Hacker.Treeview.Heading",
            background="#000000",  # Black heading
            foreground="#00ff00",  # Neon green text
            font=("Consolas", 12, "bold")
        )

    def setup_ui(self):
        """
        Set up the hacker-style GUI layout.
        """
        # Main Frame
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.configure(style="Hacker.TLabel")

        # Control Buttons
        button_frame = ttk.Frame(main_frame, padding=5)
        button_frame.grid(row=0, column=0, columnspan=2, pady=10, sticky="ew")
        button_frame.columnconfigure((0, 1, 2), weight=1)

        self.start_button = ttk.Button(
            button_frame, text="Start Sniffing", command=self.start_sniffing, style="Hacker.TButton"
        )
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = ttk.Button(
            button_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED, style="Hacker.TButton"
        )
        self.stop_button.grid(row=0, column=1, padx=5)

        self.export_button = ttk.Button(
            button_frame, text="Export Logs", command=self.export_logs, state=tk.DISABLED, style="Hacker.TButton"
        )
        self.export_button.grid(row=0, column=2, padx=5)

        # Packet Log Treeview
        log_frame = ttk.LabelFrame(main_frame, text="Packet Logs", padding=5, style="Hacker.TLabel")
        log_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=10)

        columns = ("Source IP", "Destination IP", "Protocol", "Source MAC", "Destination MAC", "Message")
        self.log_tree = ttk.Treeview(log_frame, columns=columns, show="headings", height=25, style="Hacker.Treeview")

        for col in columns:
            width = 200 if col != "Message" else 400  # Increased width for the "Message" column
            self.log_tree.heading(col, text=col)
            self.log_tree.column(col, width=width, anchor="center")

        self.log_tree.pack(fill="both", expand=True)

        # Make window resizable
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)

    def log_message(self, src_ip, dst_ip, protocol, src_mac, dst_mac, message):
        """
        Add a log entry to the Treeview.
        """
        self.log_tree.insert("", "end", values=(src_ip, dst_ip, protocol, src_mac, dst_mac, message))
        self.log_tree.yview_moveto(1)

    def process_packet(self, packet):
        """
        Process packets to display their details and detect ARP spoofing.
        """
        src_ip, dst_ip, protocol, alert_message = "N/A", "N/A", "OTHER", ""
        src_mac, dst_mac = "N/A", "N/A"

        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "IP"

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ARP):
            protocol = "ARP"
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc

            if packet[ARP].op == 2:  # ARP Reply
                if src_mac not in self.arp_table[src_ip]:
                    if len(self.arp_table[src_ip]) > 0:
                        alert_message = f"[ALERT] ARP Spoof Detected: {src_ip} is claimed by {src_mac}."
                        messagebox.showwarning("ARP Spoof Detected", alert_message)
                    else:
                        alert_message = f"[INFO] New ARP Entry: {src_ip} -> {src_mac}"
                self.arp_table[src_ip].add(src_mac)

        # Log the packet details
        self.log_message(src_ip, dst_ip, protocol, src_mac, dst_mac, alert_message)

    def start_sniffing(self):
        """
        Start sniffing packets in a separate thread.
        """
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.DISABLED)
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        """
        Stop sniffing packets.
        """
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.export_button.config(state=tk.NORMAL)

    def sniff_packets(self):
        """
        Sniff packets and process them.
        """
        sniff(store=False, prn=self.process_packet, stop_filter=lambda _: not self.sniffing)

    def export_logs(self):
        """
        Export logs to a file.
        """
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if file_path:
            with open(file_path, "w") as f:
                for row in self.log_tree.get_children():
                    row_data = self.log_tree.item(row)["values"]
                    f.write(",".join(str(x) for x in row_data) + "\n")
            messagebox.showinfo("Export Successful", f"Logs exported to {file_path}")


# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()