__version__ = '0.3'
__author__ = 'Oren Brigg'
__author_email__ = 'obrigg@cisco.com'
__license__ = "Cisco Sample Code License, Version 1.1 - https://developer.cisco.com/site/license/cisco-sample-code-license/"


import meraki
from rich import print as pp
from rich.console import Console
from rich.table import Table
from openpyxl import Workbook
from openpyxl.styles import Font, Color


def select_org():
    # Fetch and select the organization
    print('\n\nFetching organizations...\n')
    organizations = dashboard.organizations.getOrganizations()
    ids = []
    table = Table(title="Meraki Organizations")
    table.add_column("Organization #", justify="left", style="cyan", no_wrap=True)
    table.add_column("Org Name", justify="left", style="cyan", no_wrap=True)
    counter = 0
    for organization in organizations:
        ids.append(organization['id'])
        table.add_row(str(counter), organization['name'])
        counter+=1
    console = Console()
    console.print(table)
    isOrgDone = False
    while isOrgDone == False:
        selected = input('\nKindly select the organization ID you would like to query: ')
        try:
            if int(selected) in range(0,counter):
                isOrgDone = True
            else:
                print('\t[red]Invalid Organization Number\n')
        except:
            print('\t[red]Invalid Organization Number\n')
    return(organizations[int(selected)]['id'], organizations[int(selected)]['name'])


def check_network_health_alerts(network_id: str) -> dict:
    """
    This fuction checks the network health alerts for a given network. 
    """
    print("\n\t\tChecking network health alerts...\n")
    alerts = dashboard.networks.getNetworkHealthAlerts(network_id)
    if len(alerts) == 0:
        pp(f"[green]No network health alerts for network {network_id}")
        return({'is_ok': True})
    else:
        result = {'is_ok': False, 'alert_list': []}
        pp(f"[red]Network alerts detected for network {network_id}")
        for alert in alerts:
            try:
                del alert['scope']['devices'][0]['url']
                del alert['scope']['devices'][0]['mac']
            except:
                pass
            result['alert_list'].append({'severity': alert['severity'], 'category': alert['category'], 'type': alert['type'], 'details': alert['scope']})
            pp(f"[red]Severity: {alert['severity']}\tCategory: {alert['category']}\tType: {alert['type']}")
        return(result)


def check_wifi_channel_utilization(network_id: str) -> dict:
    """
    This fuction checks the wifi channel utilization for a given network. 
    if the channel utilization is above the threshold, the check will fail.

    it will return a dictionary with the result for each AP.
    e.g. {
    'is_ok': False,
    'Q2KD-XXXX-XXXX': {'is_ok': False, 'name': 'AP1', 'utilization': 51.66, 'occurances': 3},
    'Q2KD-XXXX-XXXX': {'is_ok': False, 'name': 'AP2', 'utilization': 56.69, 'occurances': 17},
    'Q2KD-XXXX-XXXX': {'is_ok': True, 'name': 'AP3', 'utilization': 16.93, 'occurances': 8},
    'Q2KD-XXXX-XXXX': {'is_ok': False, 'name': 'AP4', 'utilization': 59.48, 'occurances': 1}
    }
    """
    print("\n\t\tChecking wifi channel utilization...\n")
    result = {'is_ok': True}
    channel_utilization = dashboard.networks.getNetworkNetworkHealthChannelUtilization(network_id, perPage=100)
    # TODO: pagination
    for ap in channel_utilization:
        utilization_list = [ap['wifi1'][util]['utilization'] for util in range(len(ap['wifi1']))]
        exceeded_utilization_list = [utilization for utilization in utilization_list if utilization > thresholds['5G Channel Utilization']]
        if len(utilization_list) == 0:
            pp(f"[yellow]AP {ap['serial']} does not have 5GHz enabled. Skipping...")
        elif len(exceeded_utilization_list) > 0:
            pp(f"[red]5G Channel Utilization exceeded {thresholds['5G Channel Utilization']}% {len(exceeded_utilization_list)} times, with a peak of {max(utilization_list)}% for AP {ap['serial']}")
            result[ap['serial']] = {'is_ok': False, 'utilization': max(utilization_list), 'occurances': len(exceeded_utilization_list)}
            result['is_ok'] = False
        else:
            pp(f"[green]5G Channel did not exceed {thresholds['5G Channel Utilization']}% for AP {ap['serial']}, max utilization was {max(utilization_list)}")
            result[ap['serial']] = {'is_ok': True, 'utilization': max(utilization_list), 'occurances': ''}
    # Adding AP names
    network_devices = dashboard.networks.getNetworkDevices(network_id)
    for device in network_devices:
        if device['serial'] in result:
            result[device['serial']]['name'] = device['name']
    #
    return result


def check_wifi_rf_profiles(network_id: str) -> dict:
    """
    This fuction checks the RF profiles for a given network. 

    it will return a dictionary with the result for each AP.
    e.g. {
    'is_ok': False,
    'RF Profile 1': {'is_ok': False, 'min_power': 30, 'min_bitrate': 12, 'channel_width': '80', 'rxsop': None},
    'RF Profile 2': {'is_ok': True, 'min_power': 2, 'min_bitrate': 12, 'channel_width': 'auto', 'rxsop': None}
    }

    """
    print("\n\t\tChecking WiFi RF Profiles...\n")
    result = {'is_ok': True}
    rf_profiles = dashboard.wireless.getNetworkWirelessRfProfiles(network_id)
    for rf_profile in rf_profiles:
        result[rf_profile['name']] = {  'is_ok': True, 
                                        'tests': {
                                            'min_power': {'is_ok': True},
                                            'min_bitrate': {'is_ok': True},
                                            'channel_width': {'is_ok': True},
                                            'rxsop': {'is_ok': True}
                                        }}
        # Check min TX power
        if rf_profile['fiveGhzSettings']['minPower'] > thresholds['5G Min TX Power']:
            pp(f"[red]The min TX power is too high at {rf_profile['fiveGhzSettings']['minPower']}dBm (not including antenna gain) for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['min_power'] = {'is_ok': False, 'value': rf_profile['fiveGhzSettings']['minPower']}
            result[rf_profile['name']]['is_ok'] = False
            result['is_ok'] = False
        else:
            pp(f"[green]The min TX power is {rf_profile['fiveGhzSettings']['minPower']}dBm for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['min_power'] = {'is_ok': True, 'value': rf_profile['fiveGhzSettings']['minPower']}
        
        # Check min bitrate
        if rf_profile['fiveGhzSettings']['minBitrate'] < thresholds['5G Min Bitrate']:
            pp(f"[red]The min bitrate is {rf_profile['fiveGhzSettings']['minBitrate']}Mbps for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['min_bitrate'] = {'is_ok': False, 'value': rf_profile['fiveGhzSettings']['minBitrate']}
            result[rf_profile['name']]['is_ok'] = False
            result['is_ok'] = False
        else:
            pp(f"[green]The min bitrate is {rf_profile['fiveGhzSettings']['minBitrate']}Mbps for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['min_bitrate'] = {'is_ok': True, 'value': rf_profile['fiveGhzSettings']['minBitrate']}
        
        # Check channel width
        if rf_profile['fiveGhzSettings']['channelWidth'] == "auto":
            pp(f"[red]The channel width is {rf_profile['fiveGhzSettings']['channelWidth']} for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['channel_width'] = {'is_ok': False, 'value': rf_profile['fiveGhzSettings']['channelWidth']}
            result[rf_profile['name']]['is_ok'] = False
            result['is_ok'] = False
        elif int(rf_profile['fiveGhzSettings']['channelWidth']) > thresholds['5G Max Channel Width']:
            pp(f"[red]The channel width is {rf_profile['fiveGhzSettings']['channelWidth']}MHz for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['channel_width'] = {'is_ok': False, 'value': rf_profile['fiveGhzSettings']['channelWidth']}
            result[rf_profile['name']]['is_ok'] = False
            result['is_ok'] = False
        else:
            pp(f"[green]The channel width is {rf_profile['fiveGhzSettings']['channelWidth']}MHz for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['channel_width'] = {'is_ok': True, 'value': rf_profile['fiveGhzSettings']['channelWidth']}
        
        # Check if rx-sop is confiugred
        if rf_profile['fiveGhzSettings']['rxsop'] != None:
            pp(f"[red]RX-SOP is configured for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['rxsop'] = {'is_ok': False, 'value': rf_profile['fiveGhzSettings']['rxsop']}
            result[rf_profile['name']]['is_ok'] = False
            result['is_ok'] = False
        else:
            pp(f"[green]RX-SOP is not configured for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['rxsop'] = {'is_ok': True, 'value': rf_profile['fiveGhzSettings']['rxsop']}
    return (result)


def check_wifi_ssid_amount(network_id: str) -> dict:
    """
    This fuction checks the amount of SSIDs for a given network. 

    e.g. {
    'is_ok': False,
    'amount': 5
    }
    """
    print("\n\t\tChecking WiFi SSID Amount...\n")
    result = {'is_ok': True}
    ssid_list = dashboard.wireless.getNetworkWirelessSsids(network_id)
    enabled_ssid_counter = 0
    for ssid in ssid_list:
        if ssid['enabled']:
            enabled_ssid_counter += 1
    result['ssid_amount'] = enabled_ssid_counter
    if enabled_ssid_counter <= thresholds['ssid_amount']:
        pp(f"[green]There are {enabled_ssid_counter} SSIDs enabled for network {network_id}")
    else:
        pp(f"[red]There are {enabled_ssid_counter} SSIDs enabled for network {network_id}")
        result['is_ok'] = False
    return (result)


def check_switch_port_counters(network_id: str) -> dict:
    """
    This fuction checks the port counters for all switches in a given network. 

    it will return a dictionary with the result for each switch.
    e.g. {
    'is_ok': False,
    'Switch 1': {'is_ok': False, 'crc': ['3'], 'collision': [], 'broadcast': ['17', '18', '19', '20', '27'], 'multicast': [], 'topology_changes': []},
    'Switch 2': {'is_ok': False, 'crc': [], 'collision': ['5'], 'broadcast': ['1', '14', '49'], 'multicast': [], 'topology_changes': []},
    'Switch 3': {'is_ok': True, 'crc': [], 'collision': [], 'broadcast': [], 'multicast': [], 'topology_changes': []},
    }
    """
    print("\n\t\tChecking Switch Port Counters...\n")
    result = {'is_ok': True}
    device_list = dashboard.networks.getNetworkDevices(network_id)
    for device in device_list:
        if "MS" in device['model']:
            if "name" not in device.keys():
                device["name"] = device["serial"]
            result[device['name']] = {'is_ok': True, 'crc': [], 'collision': [], 'broadcast': [], 'multicast': [], 'topology_changes': []}
            switch_counters = dashboard.switch.getDeviceSwitchPortsStatusesPackets(device['serial'])
            for port in switch_counters:
                for port_counter in port['packets']:
                    # CRC and collision errors
                    if port_counter['desc'] == "CRC align errors" and port_counter['total'] > 0:
                        pp(f"[red]{port_counter['total']} CRC errors on switch {device['name']} - port {port['portId']}")
                        result[device['name']]['crc'].append(port['portId'])
                        result[device['name']]['is_ok'] = False
                        result['is_ok'] = False
                    elif port_counter['desc'] == "Collisions" and port_counter['total'] > 0:
                        pp(f"[red]{port_counter['total']} collisions on switch {device['name']} - port {port['portId']}")
                        result[device['name']]['collision'].append(port['portId'])
                        result[device['name']]['is_ok'] = False
                        result['is_ok'] = False
                    # Broadcast and Multicast rates
                    elif port_counter['desc'] == "Broadcast" and port_counter['ratePerSec']['total'] > thresholds['broadcast_rate']:
                        pp(f"[red]{port_counter['ratePerSec']['total']} broadcast/s on switch {device['name']} - port {port['portId']}")
                        result[device['name']]['broadcast'].append(port['portId'])
                        result[device['name']]['is_ok'] = False
                        result['is_ok'] = False
                    elif port_counter['desc'] == "Multicast" and port_counter['ratePerSec']['total'] > thresholds['multicast_rate']:
                        pp(f"[red]{port_counter['ratePerSec']['total']} multicast/s on switch {device['name']} - port {port['portId']}")
                        result[device['name']]['multicast'].append(port['portId'])
                        result[device['name']]['is_ok'] = False
                        result['is_ok'] = False
                    # Topology changes
                    elif port_counter['desc'] == "Topology changes" and port_counter['total'] > thresholds['topology_changes']:
                        pp(f"[red]{port_counter['total']} topology changes on switch {device['name']} - port {port['portId']}")
                        result[device['name']]['topology_changes'].append(port['portId'])
                        result[device['name']]['is_ok'] = False
                        result['is_ok'] = False
    return(result)


def check_switch_stp(network_id: str) -> dict:
    """
    This fuction checks the STP status for a given network. 
    """
    print("\n\t\tChecking Switch STP Status...\n")
    stp_status = dashboard.switch.getNetworkSwitchStp(network_id)
    if stp_status['rstpEnabled']:
        pp(f"[green]STP is enabled for network {network_id}")
        return({'is_ok': True})
    else:
        pp(f"[red]STP is disabled for network {network_id}")
        return({'is_ok': False})


def check_switch_mtu(network_id: str) -> dict:
    """
    This fuction checks the MTU of a given network. 
    """
    print("\n\t\tChecking Switch MTU...\n")
    mtu = dashboard.switch.getNetworkSwitchMtu(network_id)
    if mtu['defaultMtuSize'] > 9100 or mtu['overrides'] == []:
        pp(f"[green]Jumbo Frames enabled for network {network_id} (MTU: {mtu['defaultMtuSize']})")
        return({'is_ok': True})
    else:
        pp(f"[red]Jumbo Frames disabled for network {network_id} (MTU: {mtu['defaultMtuSize']}).\
            \nIt's recommended to keep at default of 9578 unless intermediate devices don’t support jumbo frames")
        return({'is_ok': False})


def check_switch_storm_control(network_id: str) -> dict:
    """
    This fuction checks the storm control settings of a given network. 
    """
    print("'n\t\tChecking Switch Storm Control...\n")
    storm_control = dashboard.switch.getNetworkSwitchStormControl(network_id)
    if storm_control['broadcastThreshold'] < 100 and storm_control['multicastThreshold'] < 100 and storm_control['unknownUnicastThreshold'] < 100:
        pp(f"[green]Storm-control is enabled for network {network_id}.")
        return({'is_ok': True})
    else:
        pp(f"[yellow]Storm-control is disabled for network {network_id}. Best practices suggest a limit should be configured.")
        return({'is_ok': False})


def generate_excel_report(results: dict) -> None:
    print("\n\t\tGenerating an Excel Report...\n")
    workbook = Workbook()
    sheet = workbook.active
    #
    # Summary tab
    sheet.title = "Summary"
    sheet["A1"] = "Organization Name"
    sheet["B1"] = "Network Name"
    sheet["C1"] = "Test Name"
    sheet["D1"] = "Test Result"
    line = 2
    #
    for network in results:
        for test_name in results[network]:
            sheet[f"A{line}"] = org_name
            sheet[f"B{line}"] = network
            sheet[f"C{line}"] = test_name
            if results[network][test_name]['is_ok']:
                sheet[f"D{line}"] = "Pass"
            else:
                sheet[f"D{line}"] = "Fail"
                sheet[f"D{line}"].font = Font(bold=True, color="00FF0000")
            line += 1
    #
    # Network Health Alerts tab
    workbook.create_sheet("Network Health Alerts")
    sheet = workbook["Network Health Alerts"]
    sheet["A1"] = "Organization Name"
    sheet["B1"] = "Network Name"
    sheet["C1"] = "Severity"
    sheet["D1"] = "Category"
    sheet["E1"] = "Type"
    sheet["F1"] = "Details"
    line = 2
    #
    for network in results:
        if results[network]['network_health_alerts']['is_ok'] == True:
            pass
        else:
            for alert in results[network]['network_health_alerts']['alert_list']:
                sheet[f"A{line}"] = org_name
                sheet[f"B{line}"] = network
                sheet[f"C{line}"] = alert['severity']
                sheet[f"D{line}"] = alert['category']
                sheet[f"E{line}"] = alert['type']
                sheet[f"F{line}"] = str(alert['details'])
                if alert['severity'] == "critical":
                    for cell in sheet[line:line]:
                        cell.font = Font(bold=True, color="00FF0000")
                elif alert['severity'] == "warning":
                    for cell in sheet[line:line]:
                        cell.font = Font(bold=True, color="00FF9900")
                line += 1   
    #
    # Channel Utilization tab
    workbook.create_sheet("Channel Utilization")
    sheet = workbook["Channel Utilization"]
    sheet["A1"] = "Organization Name"
    sheet["B1"] = "Network Name"
    sheet["C1"] = "AP Name"
    sheet["D1"] = "Result"
    sheet["E1"] = "Max Utilization"
    sheet["F1"] = "Occurances"
    line = 2
    #
    for network in results:
        if "channel_utilization_check" in results[network].keys():
            for ap in results[network]['channel_utilization_check']:
                if ap == "is_ok":   # skipping the is_ok key
                    continue
                sheet[f"A{line}"] = org_name
                sheet[f"B{line}"] = network
                sheet[f"C{line}"] = results[network]['channel_utilization_check'][ap]['name']
                if results[network]['channel_utilization_check'][ap]['is_ok']:
                    sheet[f"D{line}"] = "Pass"
                else:
                    sheet[f"D{line}"] = "Fail"
                    sheet[f"D{line}"].font = Font(bold=True, color="00FF0000")
                    sheet[f"E{line}"].font = Font(bold=True, color="00FF0000")
                sheet[f"E{line}"] = results[network]['channel_utilization_check'][ap]['utilization']
                sheet[f"F{line}"] = results[network]['channel_utilization_check'][ap]['occurances']
                line += 1
    #
    # RF Profile tab
    workbook.create_sheet("RF Profiles")
    sheet = workbook["RF Profiles"]
    sheet["A1"] = "Organization Name"
    sheet["B1"] = "Network Name"
    sheet["C1"] = "RF Profile"
    sheet["D1"] = "Result"
    sheet["E1"] = "Minimum TX Power"
    sheet["F1"] = "Minimum Bit Rate"
    sheet["G1"] = "Channel Width"
    sheet["H1"] = "RX-SOP"
    line = 2
    #
    for network in results:
        if "rf_profiles_check" in results[network].keys():
            for profile in results[network]['rf_profiles_check']:
                if profile == "is_ok":  # skipping the is_ok key
                    continue
                sheet[f"A{line}"] = org_name
                sheet[f"B{line}"] = network
                sheet[f"C{line}"] = profile
                if results[network]['rf_profiles_check'][profile]['is_ok']:
                    sheet[f"D{line}"] = "Pass"
                else:
                    sheet[f"D{line}"] = "Fail"
                    sheet[f"D{line}"].font = Font(bold=True, color="00FF0000")
                    sheet[f"E{line}"] = results[network]['rf_profiles_check'][profile]['tests']['min_power']['value']
                    if results[network]['rf_profiles_check'][profile]['tests']['min_power']['is_ok'] == False:
                        sheet[f"E{line}"].font = Font(bold=True, color="00FF0000")
                    #
                    sheet[f"F{line}"] = results[network]['rf_profiles_check'][profile]['tests']['min_bitrate']['value']
                    if results[network]['rf_profiles_check'][profile]['tests']['min_bitrate']['is_ok'] == False:
                        sheet[f"F{line}"].font = Font(bold=True, color="00FF0000")
                    #
                    sheet[f"G{line}"] = results[network]['rf_profiles_check'][profile]['tests']['channel_width']['value']
                    if results[network]['rf_profiles_check'][profile]['tests']['channel_width']['is_ok'] == False:
                        sheet[f"G{line}"].font = Font(bold=True, color="00FF0000")
                    #
                    sheet[f"H{line}"] = results[network]['rf_profiles_check'][profile]['tests']['rxsop']['value']
                    if results[network]['rf_profiles_check'][profile]['tests']['rxsop']['is_ok'] == False:
                        sheet[f"H{line}"].font = Font(bold=True, color="00FF0000")
                line += 1
    #
    # Switch ports tab
    workbook.create_sheet("Switch port counters")
    sheet = workbook["Switch port counters"]
    sheet["A1"] = "Organization Name"
    sheet["B1"] = "Network Name"
    sheet["C1"] = "Switch"
    sheet["D1"] = "Result"
    sheet["E1"] = "Ports with CRC errors"
    sheet["F1"] = "Ports with collisions"
    sheet["G1"] = "Multicasts exceeding threshold"
    sheet["H1"] = "Broadcasts exceeding threshold"
    sheet["I1"] = "Topology changes exceeding threshold"
    line = 2
    #
    for network in results:
        if "port_counters_check" in results[network].keys():
            for switch in results[network]['port_counters_check']:
                if switch == "is_ok":   # skipping the is_ok key
                    continue
                sheet[f"A{line}"] = org_name
                sheet[f"B{line}"] = network
                sheet[f"C{line}"] = switch
                if results[network]['port_counters_check'][switch]['is_ok']:
                    sheet[f"D{line}"] = "Pass"
                else:
                    sheet[f"D{line}"] = "Fail"
                    sheet[f"D{line}"].font = Font(bold=True, color="00FF0000")
                if results[network]['port_counters_check'][switch]['crc'] != []:
                    sheet[f"E{line}"] = str(results[network]['port_counters_check'][switch]['crc'])
                    sheet[f"E{line}"].font = Font(bold=True, color="00FF0000")
                if results[network]['port_counters_check'][switch]['collision'] != []:
                    sheet[f"F{line}"] = str(results[network]['port_counters_check'][switch]['collision'])
                    sheet[f"F{line}"].font = Font(bold=True, color="00FF0000")
                if results[network]['port_counters_check'][switch]['multicast'] != []:
                    sheet[f"G{line}"] = str(results[network]['port_counters_check'][switch]['multicast'])
                    sheet[f"G{line}"].font = Font(bold=True, color="00FF0000")
                if results[network]['port_counters_check'][switch]['broadcast'] != []:
                    sheet[f"H{line}"] = str(results[network]['port_counters_check'][switch]['broadcast'])
                    sheet[f"H{line}"].font = Font(bold=True, color="00FF0000")
                if results[network]['port_counters_check'][switch]['topology_changes'] != []:
                    sheet[f"I{line}"] = str(results[network]['port_counters_check'][switch]['topology_changes'])
                    sheet[f"I{line}"].font = Font(bold=True, color="00FF0000")
                line += 1
    #
    workbook.save(filename=f"{org_name}.xlsx")


if __name__ == '__main__':
    # Thresholds
    thresholds = {
        '5G Channel Utilization': 20,   # %
        '5G Min TX Power': 10,          # dBm
        '5G Min Bitrate': 12,           # Mbps
        '5G Max Channel Width': 40,     # MHz
        'broadcast_rate': 100,           # pps
        'multicast_rate': 100,            # pps
        'topology_changes': 10,
        'ssid_amount': 4
    }

    # Initializing Meraki SDK
    dashboard = meraki.DashboardAPI(output_log=False, suppress_logging=True)
    org_id, org_name = select_org()
    results = {}
    
    # Get networks
    networks = dashboard.organizations.getOrganizationNetworks(org_id)
    for network in networks:
        network_id = network['id']
        results[network['name']] = {}
        pp(f"[bold magenta]\n{90*'*'}")
        pp(f"[bold magenta]{10*'*' : <30}{' ' : ^30}{10*'*' : >30}")
        pp(f"[bold magenta]{10*'*' : <30}{network['name'] : ^30}{10*'*' : >30}")
        pp(f"[bold magenta]{10*'*' : <30}{' ' : ^30}{10*'*' : >30}")
        pp(f"[bold magenta]{90*'*'}\n")
        # General checks
        results[network['name']]['network_health_alerts'] = check_network_health_alerts(network_id)
        
        if "wireless" in network['productTypes']:
            # Wireless checks
            try:
                results[network['name']]['channel_utilization_check'] = check_wifi_channel_utilization(network_id)
            except:
                pp(f"[yellow]The network {network_id} does not support channel-utilization reporting. It should probably be upgraded...")
            results[network['name']]['rf_profiles_check'] = check_wifi_rf_profiles(network_id)
            results[network['name']]['ssid_amount_check'] = check_wifi_ssid_amount(network_id)
            # TODO: wireless health
        
        if "switch" in network['productTypes']:
            # Wired checks
            results[network['name']]['port_counters_check'] = check_switch_port_counters(network_id)
            results[network['name']]['stp_check'] = check_switch_stp(network_id)
            results[network['name']]['mtu_check'] = check_switch_mtu(network_id)
            try:
                results[network['name']]['storm_control_check'] = check_switch_storm_control(network_id)
            except:
                pp(f"[yellow]The network {network_id} does not support storm-control")
            # TODO: check for large broadcast domains / number of clients on a Vlan
    
    pp("\n", 100*"*", "\n")
    # Results cleanup
    clean_results = {}
    for result in results:
        if results[result] != {}:
            clean_results[result] = results[result]

    pp(clean_results)
    generate_excel_report(clean_results)
