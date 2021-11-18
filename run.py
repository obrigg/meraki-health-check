__version__ = '1'
__author__ = 'Oren Brigg - obrigg@cisco.com'
__license__ = "Cisco Sample Code License, Version 1.1 - https://developer.cisco.com/site/license/cisco-sample-code-license/"


import meraki
from rich import print as pp
from rich.console import Console
from rich.table import Table
from rich.progress import track


def select_network() -> str:
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
    # Fetch and select the network within the organization
    print('\n\nFetching networks...\n')
    networks = dashboard.organizations.getOrganizationNetworks(organizations[int(selected)]['id'])
    ids = []
    table = Table(title="Available Networks")
    table.add_column("Network #", justify="left", style="green", no_wrap=True)
    table.add_column("Network Name", justify="left", style="green", no_wrap=True)
    counter = 0
    for network in networks:
        ids.append(network['id'])
        table.add_row(str(counter), network['name'])
        counter += 1
    console = Console()
    console.print(table)
    isNetDone = False
    while isNetDone == False:
        selected = input('\nKindly select the Network you would like to query: ')
        try:
            if int(selected) in range(0,counter):
                isNetDone = True
            else:
                print('\t[bold red]Invalid Organization Number\n')
        except:
            print('\t[bold red]Invalid Organization Number\n')
    return(networks[int(selected)]['id'])


def check_wifi_channel_utilization(network_id: str, threshold: int) -> dict:
    """
    This fuction checks the wifi channel utilization for a given network. 
    if the channel utilization is above the threshold, the check will fail.

    it will return a dictionary with the result for each AP.
    e.g. {
    'Q2KD-XXXX-XXXX': {'result': 'FAIL', 'utilization': 51.66},
    'Q2KD-XXXX-XXXX': {'result': 'FAIL', 'utilization': 56.69},
    'Q2KD-XXXX-XXXX': {'result': 'PASS', 'utilization': 16.93},
    'Q2KD-XXXX-XXXX': {'result': 'FAIL', 'utilization': 59.48}
    }
    """
    result = {}
    channel_utilization = dashboard.networks.getNetworkNetworkHealthChannelUtilization(network_id)
    for ap in channel_utilization:
        max_util = 0
        for util in ap['wifi1']:
            if util['utilization'] > max_util:
                max_util = util['utilization']
        if max_util > threshold:
            pp(f"[bold red]5G Channel Utilization reached {max_util}% - above {threshold}% for AP {ap['serial']}")
            result[ap['serial']] = {'result': 'FAIL', 'utilization': max_util}
        elif max_util == 0:
            print(f"AP {ap['serial']} does not have 5GHz enabled. Skipping...")
        else:
            pp(f"[green]5G Channel Utilization reached {max_util}% - below {threshold}% for AP {ap['serial']}")
            result[ap['serial']] = {'result': 'PASS', 'utilization': max_util}
    return result


def check_wifi_rf_profiles(network_id: str) -> dict:
    """
    This fuction checks the RF profiles for a given network. 

    it will return a dictionary with the result for each AP.
    e.g. {
    'RF Profile 1': {'result': 'FAIL', 'min_power': 30, 'min_bitrate': 12, 'channel_width': '80', 'rxsop': None},
    'RF Profile 2': {'result': 'FAIL', 'min_power': 2, 'min_bitrate': 12, 'channel_width': 'auto', 'rxsop': None}
    }

    """
    result = {}
    rf_profiles = dashboard.wireless.getNetworkWirelessRfProfiles(network_id)
    for rf_profile in rf_profiles:
        result[rf_profile['name']] = {'result': 'PASS'}
        # Check min TX power
        if rf_profile['fiveGhzSettings']['minPower'] > 10:
            pp(f"[bold red]The min TX power is too high at {rf_profile['fiveGhzSettings']['minPower']}dBm (not including antenna gain) for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['result'] = 'FAIL'
            result[rf_profile['name']]['min_power'] = rf_profile['fiveGhzSettings']['minPower']
        else:
            pp(f"[green]The min TX power is {rf_profile['fiveGhzSettings']['minPower']}dBm for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['min_power'] = rf_profile['fiveGhzSettings']['minPower']
        # Check min bitrate
        if rf_profile['fiveGhzSettings']['minBitrate'] < 36:
            pp(f"[bold red]The min bitrate is {rf_profile['fiveGhzSettings']['minBitrate']}Mbps for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['result'] = 'FAIL'
            result[rf_profile['name']]['min_bitrate'] = rf_profile['fiveGhzSettings']['minBitrate']
        else:
            pp(f"[green]The min bitrate is {rf_profile['fiveGhzSettings']['minBitrate']}Mbps for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['min_bitrate'] = rf_profile['fiveGhzSettings']['minBitrate']
        # Check channel width
        if rf_profile['fiveGhzSettings']['channelWidth'] == "auto":
            pp(f"[bold red]The channel width is {rf_profile['fiveGhzSettings']['channelWidth']} for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['result'] = 'FAIL'
            result[rf_profile['name']]['channel_width'] = rf_profile['fiveGhzSettings']['channelWidth']
        elif int(rf_profile['fiveGhzSettings']['channelWidth']) > 40:
            pp(f"[bold red]The channel width is {rf_profile['fiveGhzSettings']['channelWidth']}MHz for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['result'] = 'FAIL'
            result[rf_profile['name']]['channel_width'] = rf_profile['fiveGhzSettings']['channelWidth']
        else:
            pp(f"[green]The channel width is {rf_profile['fiveGhzSettings']['channelWidth']}MHz for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['channel_width'] = rf_profile['fiveGhzSettings']['channelWidth']
        # Check if rx-sop is confiugred
        if rf_profile['fiveGhzSettings']['rxsop'] != None:
            pp(f"[red]RX-SOP is configured for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['result'] = 'FAIL'
            result[rf_profile['name']]['rxsop'] = rf_profile['fiveGhzSettings']['rxsop']
        else:
            pp(f"[green]RX-SOP is not configured for RF profile {rf_profile['name']}")
            result[rf_profile['name']]['rxsop'] = rf_profile['fiveGhzSettings']['rxsop']
    return result

if __name__ == '__main__':
    # Debug mode
    isDebug = False
    # Initializing Meraki SDK
    dashboard = meraki.DashboardAPI()
    network_id = select_network()
    results = {}
    
    # Wireless checks
    pp(3*"\n", 100*"*", 3*"\n")
    results['channel_utilization_check'] = check_wifi_channel_utilization(network_id, 20)
    pp(3*"\n", 100*"*", 3*"\n")
    results['rf_profiles_check'] = check_wifi_rf_profiles(network_id)
    pp(3*"\n", 100*"*", 3*"\n")
        # TODO: wireless health
    # Wired checks
        # TODO: check for CRCs
        # TODO: check for broadcasts/multicasts
        # TODO: check for large broadcast domains / number of clients on a Vlan

    pp(3*"\n", 100*"*", 3*"\n")
    pp(results)