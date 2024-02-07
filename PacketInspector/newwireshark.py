import csv
from scapy.all import *

def generate_report(file_path):
    packets = rdpcap(file_path)  # Read packets from the Wireshark file

    report = []

    for packet in packets:
        # Extract relevant information from each packet
        time = packet.time
        source = packet.src
        destination = packet.dst
        protocol = packet.name
        length = len(packet)
        info = packet.summary()

        # Append information to the report list
        report.append({
            'Time': time,
            'Source': source,
            'Destination': destination,
            'Protocol': protocol,
            'Length': length,
            'Info': info
        })

    return report

def save_report_to_csv(report, csv_file_path):
    with open(csv_file_path, 'w', newline='') as csv_file:
        fieldnames = ['Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        # Write the header
        writer.writeheader()

        # Write each entry to the CSV file
        for entry in report:
            writer.writerow(entry)

if __name__ == "__main__":
    wireshark_file_path = r"C:\Users\Venkatesh Mahadik\Downloads\test.pcapng"
    generated_report = generate_report(wireshark_file_path)

    csv_file_path = "generated_report.csv"
    save_report_to_csv(generated_report, csv_file_path)

    print(f"Report saved to {csv_file_path}")
