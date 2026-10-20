# SentinelX - Port Scan Detection


def detect_port_scan(log_file):

    alerts = []

    # Store contacted ports for each source IP
    ip_data = {}


    # ==========================================
    # READ NETWORK LOG
    # ==========================================

    with open(log_file, "r") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue


            # ----------------------------------
            # Extract values from the log line
            # ----------------------------------

            parts = line.split()

            if len(parts) < 5:
                continue


            # Example:
            #
            # 2026-10-20 11:00:06 connection
            # source_ip=10.0.0.25
            # destination_ip=192.168.1.10
            # destination_port=80
            # status=REJECTED


            timestamp = parts[0] + " " + parts[1]

            event_type = parts[2]


            if event_type.lower() != "connection":
                continue


            source_ip = None
            destination_ip = None
            destination_port = None
            status = None


            for part in parts[3:]:

                if part.startswith("source_ip="):

                    source_ip = part.split(
                        "=",
                        1
                    )[1]


                elif part.startswith("destination_ip="):

                    destination_ip = part.split(
                        "=",
                        1
                    )[1]


                elif part.startswith("destination_port="):

                    destination_port = part.split(
                        "=",
                        1
                    )[1]


                elif part.startswith("status="):

                    status = part.split(
                        "=",
                        1
                    )[1]


            # Ignore incomplete events

            if (
                source_ip is None
                or destination_port is None
            ):

                continue


            # ----------------------------------
            # Create IP entry
            # ----------------------------------

            if source_ip not in ip_data:

                ip_data[source_ip] = {

                    "timestamp":
                        timestamp,

                    "destination_ip":
                        destination_ip,

                    "ports":
                        []

                }


            # ----------------------------------
            # Add unique port
            # ----------------------------------

            if destination_port not in ip_data[source_ip]["ports"]:

                ip_data[source_ip]["ports"].append(
                    destination_port
                )


    # ==========================================
    # DETECT PORT SCANNING
    # ==========================================

    for source_ip, data in ip_data.items():

        ports = data["ports"]


        # 5 or more different ports
        # indicates possible scanning

        if len(ports) >= 5:

            alerts.append({

                "alert_type":
                    "Port Scan",

                "severity":
                    "MEDIUM",

                "timestamp":
                    data["timestamp"],

                "source_ip":
                    source_ip,

                "destination_ip":
                    data["destination_ip"],

                "ports":
                    ports,

                "port_count":
                    len(ports),

                "status":
                    "NEW",

                "mitre_attack": {

                    "technique_id":
                        "T1046",

                    "technique_name":
                        "Network Service Scanning"

                },

                "description":
                    (
                        f"Possible port scan detected "
                        f"from {source_ip}. "
                        f"{len(ports)} different ports "
                        f"were contacted."
                    )

            })


    return alerts