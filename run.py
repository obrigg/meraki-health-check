__version__ = '0.1'
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
                print('\t[bold red]Invalid Organization Number\n')
        except:
            print('\t[bold red]Invalid Organization Number\n')
    return(organizations[int(selected)]['id'], organizations[int(selected)]['name'])


def check_wifi_channel_utilization(network_id: str) -> dict:
    """
    This fuction checks the wifi channel utilization for a given network. 
    if the channel utilization is above the threshold, the check will fail.

    it will return a dictionary with the result for each AP.
    e.g. {
    'is_ok': False,
    'Q2KD-XXXX-XXXX': {'is_ok': False, 'utilization': 51.66},
    'Q2KD-XXXX-XXXX': {'is_ok': False, 'utilization': 56.69},
    'Q2KD-XXXX-XXXX': {'is_ok': True, 'utilization': 16.93},
    'Q2KD-XXXX-XXXX': {'is_ok': False, 'utilization': 59.48}
    }
    """
    result = {'is_ok': True}
    channel_utilization = dashboard.networks.getNetworkNetworkHealthChannelUtilization(network_id, perPage=100)
    # TODO: pagination
    for ap in channel_utilization:
        max_util = 0
        for util in ap['wifi1']:
            if util['utilization'] > max_util:
                max_util = util['utilization']
        if max_util > thresholds['5G Channel Utilization']:
            pp(f"[bold red]5G Channel Utilization reached {max_util}% - above {thresholds['5G Channel Utilization']}% for AP {ap['serial']}")
            result[ap['serial']] = {'is_ok': False, 'utilization': max_util}
            result['is_ok'] = False
        elif max_util == 0:
            print(f"AP {ap['serial']} does not have 5GHz enabled. Skipping...")
        else:
            pp(f"[green]5G Channel Utilization reached {max_util}% - below {thresholds['5G Channel Utilization']}% for AP {ap['serial']}")
            result[ap['serial']] = {'is_ok': True, 'utilization': max_util}
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
            pp(f"[bold red]The min TX power is too high at {rf_profile['fiveGhzSettings']['minPower']}dBm (not including antenna gain) for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['min_power'] = {'is_ok': False, 'value': rf_profile['fiveGhzSettings']['minPower']}
            result[rf_profile['name']]['is_ok'] = False
            result['is_ok'] = False
        else:
            pp(f"[green]The min TX power is {rf_profile['fiveGhzSettings']['minPower']}dBm for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['min_power'] = {'is_ok': True, 'value': rf_profile['fiveGhzSettings']['minPower']}
        
        # Check min bitrate
        if rf_profile['fiveGhzSettings']['minBitrate'] < thresholds['5G Min Bitrate']:
            pp(f"[bold red]The min bitrate is {rf_profile['fiveGhzSettings']['minBitrate']}Mbps for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['min_bitrate'] = {'is_ok': False, 'value': rf_profile['fiveGhzSettings']['minBitrate']}
            result[rf_profile['name']]['is_ok'] = False
            result['is_ok'] = False
        else:
            pp(f"[green]The min bitrate is {rf_profile['fiveGhzSettings']['minBitrate']}Mbps for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['min_bitrate'] = {'is_ok': True, 'value': rf_profile['fiveGhzSettings']['minBitrate']}
        
        # Check channel width
        if rf_profile['fiveGhzSettings']['channelWidth'] == "auto":
            pp(f"[bold red]The channel width is {rf_profile['fiveGhzSettings']['channelWidth']} for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['tests']['channel_width'] = {'is_ok': False, 'value': rf_profile['fiveGhzSettings']['channelWidth']}
            result[rf_profile['name']]['is_ok'] = False
            result['is_ok'] = False
        elif int(rf_profile['fiveGhzSettings']['channelWidth']) > thresholds['5G Max Channel Width']:
            pp(f"[bold red]The channel width is {rf_profile['fiveGhzSettings']['channelWidth']}MHz for RF profile {rf_profile['name']}")
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
    result = {'is_ok': True}
    device_list = dashboard.networks.getNetworkDevices(network_id)
    for device in device_list:
        if "MS" in device['model']:
            result[device['name']] = {'is_ok': True, 'crc': [], 'collision': [], 'broadcast': [], 'multicast': [], 'topology_changes': []}
            switch_counters = dashboard.switch.getDeviceSwitchPortsStatusesPackets(device['serial'])
            for port in switch_counters:
                for port_counter in port['packets']:
                    # CRC and collision errors
                    if port_counter['desc'] == "CRC align errors" and port_counter['total'] > 0:
                        pp(f"[bold red]{port_counter['total']} CRC errors on switch {device['name']} - port {port['portId']}")
                        result[device['name']]['crc'].append(port['portId'])
                        result[device['name']]['is_ok'] = False
                        result['is_ok'] = False
                    elif port_counter['desc'] == "Collisions" and port_counter['total'] > 0:
                        pp(f"[bold red]{port_counter['total']} collisions on switch {device['name']} - port {port['portId']}")
                        result[device['name']]['collision'].append(port['portId'])
                        result[device['name']]['is_ok'] = False
                        result['is_ok'] = False
                    # Broadcast and Multicast rates
                    elif port_counter['desc'] == "Broadcast" and port_counter['ratePerSec']['total'] > thresholds['broadcast_rate']:
                        pp(f"[bold red]{port_counter['ratePerSec']['total']} broadcast/s on switch {device['name']} - port {port['portId']}")
                        result[device['name']]['broadcast'].append(port['portId'])
                        result[device['name']]['is_ok'] = False
                        result['is_ok'] = False
                    elif port_counter['desc'] == "Multicast" and port_counter['ratePerSec']['total'] > thresholds['multicast_rate']:
                        pp(f"[bold red]{port_counter['ratePerSec']['total']} multicast/s on switch {device['name']} - port {port['portId']}")
                        result[device['name']]['multicast'].append(port['portId'])
                        result[device['name']]['is_ok'] = False
                        result['is_ok'] = False
                    # Topology changes
                    elif port_counter['desc'] == "Topology changes" and port_counter['total'] > thresholds['topology_changes']:
                        pp(f"[bold red]{port_counter['total']} topology changes on switch {device['name']} - port {port['portId']}")
                        result[device['name']]['topology_changes'].append(port['portId'])
                        result[device['name']]['is_ok'] = False
                        result['is_ok'] = False
    return(result)


def check_switch_stp(network_id: str) -> bool:
    """
    This fuction checks the STP status for a given network. 
    """
    stp_status = dashboard.networks.getNetworkStpStatus(network_id)
    if stp_status['rstpEnabled']:
        pp(f"[green]STP is enabled for network {network_id}")
        return(True)
    else:
        pp(f"[red]STP is disabled for network {network_id}")
        return(False)

def generate_excel_report(results: dict) -> None:
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
    # Channel Utilization tab
    workbook.create_sheet("Channel Utilization")
    sheet = workbook["Channel Utilization"]
    sheet["A1"] = "Organization Name"
    sheet["B1"] = "Network Name"
    sheet["C1"] = "AP Serial"
    sheet["D1"] = "Result"
    sheet["E1"] = "Utilization"
    line = 2
    #
    for network in results:
        if "channel_utilization_check" in results[network].keys():
            for ap in results[network]['channel_utilization_check']:
                if ap == "is_ok":   # skipping the is_ok key
                    continue
                sheet[f"A{line}"] = org_name
                sheet[f"B{line}"] = network
                sheet[f"C{line}"] = ap
                if results[network]['channel_utilization_check'][ap]['is_ok']:
                    sheet[f"D{line}"] = "Pass"
                else:
                    sheet[f"D{line}"] = "Fail"
                    sheet[f"D{line}"].font = Font(bold=True, color="00FF0000")
                    sheet[f"E{line}"].font = Font(bold=True, color="00FF0000")
                sheet[f"E{line}"] = results[network]['channel_utilization_check'][ap]['utilization']
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
                pp(profile)
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
        'topology_changes': 10
    }

    # Initializing Meraki SDK
    dashboard = meraki.DashboardAPI(output_log=False)
    org_id, org_name = select_org()
    results = {}
    
    # Get networks
    networks = dashboard.organizations.getOrganizationNetworks(org_id)
    for network in networks:
        network_id = network['id']
        results[network['name']] = {}
        if "wireless" in network['productTypes']:
            # Wireless checks
            pp(3*"\n", 100*"*", 3*"\n")
            results[network['name']]['channel_utilization_check'] = check_wifi_channel_utilization(network_id)
            pp(3*"\n", 100*"*", 3*"\n")
            results[network['name']]['rf_profiles_check'] = check_wifi_rf_profiles(network_id)
            pp(3*"\n", 100*"*", 3*"\n")
            # TODO: wireless health
        
        if "switch" in network['productTypes']:
            # Wired checks
            pp(3*"\n", 100*"*", 3*"\n")
            results[network['name']]['port_counters_check'] = check_switch_port_counters(network_id)
            pp(3*"\n", 100*"*", 3*"\n")
            results[network['name']]['stp_check'] = check_switch_stp(network_id)
            
            # TODO: check for large broadcast domains / number of clients on a Vlan
            pass

    pp(3*"\n", 100*"*", 3*"\n")
    
    # Results cleanup
    clean_results = {}
    for result in results:
        if results[result] != {}:
            clean_results[result] = results[result]

    pp(clean_results)
    generate_excel_report(clean_results)
