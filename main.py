import configparser

import requests
import json


# The main function to execute the program
def main():
    # Get response form VirusTotal API
    response = get_virus_total_response()

    # Parse data by getting the data attributes from the JSON response
    data = None
    json_response = None
    try:
        json_response = json.loads(response.text)
        data = json_response['data']['attributes']
    except:
        print("Failed to parse JSON")
        return

    # Get the SHA-256, SHA-1, and MD5 scanned files and print to screen
    scanned_file_table = get_scanned_file_table(data)
    if (scanned_file_table is not None):
        print(scanned_file_table)
    else:
        print('Scanned files table unavailable')

    # Process the data to get the results of the Scan Origin and the Scan Results
    # Print the results
    results_scan_table = get_results_scans_table(data)
    print(results_scan_table['results_table'])

    if (results_scan_table.get('scans_table') is not None):
        print(results_scan_table['scans_table'])
    else:
        print('Scan table unavailable')


# Get the user input and call the VirusTotal API which will return a response
def get_virus_total_response():
    file_id = input('Enter file hash: ')
    url = f'https://www.virustotal.com/api/v3/files/{file_id}'

    api_key = extract_api_key_from_config()
    headers = {'x-apikey': f"{api_key}"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error: {e}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")


def extract_api_key_from_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config['API']['api_key']


# Get the hashed file data and return data as a table string
def get_scanned_file_table(data):
    sha256 = data.get('sha256')
    sha1 = data.get('sha1')
    md5 = data.get('md5')
    table = None
    if (sha1 is not None or sha256 is not None or md5 is not None):
        row1 = '| _MD5_ | _SHA-1_ | _SHA-256_ |'
        break_row = '| ------ | ------ | ------|'
        row2 = f'| {md5} | {sha1} | {sha256} |'
        table = row1 + '\n' + break_row + '\n' + row2 + '\n'
    return table


# Get the last_analysis_results and process the results
def get_results_scans_table(data):
    last_analysis_results = data["last_analysis_results"]
    scans_table = None
    results_table = None
    scans_table_body = ""
    total_scans_count = 0
    positive_scans_count = 0

    # Get each result from the list of last_analysis_results
    for result in last_analysis_results:
        result_object = last_analysis_results.get(result)

        # If the result object contains data, then increment total scans and add data to the scans table
        if (result_object is not None and len(result_object) != 0):
            total_scans_count += 1

            # Store the result into the scans table body and increment the positive scans count if the scan
            # result is 'malicious'
            if (result_object.get('category') is not None and result_object.get('category') == 'malicious'):
                positive_scans_count += 1
                scans_table_body += f'| {result} | {result_object["category"]} |\n'
            elif (result_object.get('category') is not None):
                scans_table_body += f'| {result} | {result_object["category"]} |\n'
            else:
                scans_table_body += f'| {result} | N/A |\n'

    # If the scans table body is not empty, then create a scans table string
    if (len(scans_table_body) > 0):
        scans_table = '| _Scan Origin_ | _Scan Result_ |\n' + '| ------ | ------- |\n' + scans_table_body

    results_table = '| _Total Scans_ | _Positive Scans_ | \n' + '| ------ | ------ |\n' + f'| {total_scans_count} | {positive_scans_count} |\n'
    return {'results_table': results_table, 'scans_table': scans_table}


if (__name__ == '__main__'):
    main()
