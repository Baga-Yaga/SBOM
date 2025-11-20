from collections import Counter,deque,defaultdict
import zipfile
import tempfile
import json
import subprocess
import os
import shutil 
import requests
from . import code_parser as cp
SYFT_PATH = "syft"

if not shutil.which(SYFT_PATH):
    if not os.path.exists(SYFT_PATH) or not os.access(SYFT_PATH, os.X_OK):
        raise FileNotFoundError(f"Syft binary not found at '{SYFT_PATH}' and not in system PATH. "
                                "Please ensure Syft is installed and accessible.")
    elif not os.access(SYFT_PATH, os.X_OK):
        print(f"Warning: Syft binary at '{SYFT_PATH}' is not executable. Attempting to proceed, but might fail.")


def _run_syft_command(command_args, input_data=None):
    """Helper to run Syft subprocess and return JSON output."""
    full_command = [SYFT_PATH] + command_args
    print(f"Running Syft command: {' '.join(full_command)}") # For debugging

    try:
        process = subprocess.run(
            full_command,
            capture_output=True,
            text=True, 
            check=True, 
            input=input_data 
        )
    
        if not process.stdout.strip():
            raise ValueError("Syft command produced empty output. No SBOM data generated.")
        
        return json.loads(process.stdout)
    except subprocess.CalledProcessError as e:
       
        print(f"Syft command failed with error (return code {e.returncode}): {e.stderr}")
        raise RuntimeError(f"Syft command failed: {e.stderr}")
    except json.JSONDecodeError as e:
      
        print(f"Failed to parse Syft output as JSON: {e}")
        print(f"Syft stdout (partial): {process.stdout[:500]}...")
        print(f"Syft stderr: {process.stderr}")
        raise RuntimeError(f"Syft output not valid JSON: {e}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Syft command not found. Ensure '{SYFT_PATH}' is correct and executable.")
    except Exception as e:
        print(f"An unexpected error occurred while running Syft: {e}")
        raise


def process_zip_project(zip_filepath):
    """Unzips a project and runs Syft on the extracted directory."""
    print(f"Processing ZIP file: {zip_filepath}")
    with tempfile.TemporaryDirectory() as temp_dir:

        with zipfile.ZipFile(zip_filepath, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        command_args = [
            "scan",
            f"dir:{temp_dir}", # Correct f-string usage
            "--output", "cyclonedx-json", # Specify JSON output
            "--quiet", # Suppress verbose logging to stdout
            "--exclude", "**/testdata/*",
            "--exclude", "**/.git/*",
            "--exclude", "**/node_modules/*",
            "--exclude", "**/__pycache__/*",
            "--exclude", "**/target/*",
            "--exclude", "**/build/*",
            "--exclude", "**/dist/*",
            "--exclude", "**/templates/*",
            "--enrich", "all",
        ]
        return _run_syft_command(command_args)

def process_dependency_file(dep_filepath):
    print(f"Processing dependency file: {dep_filepath}")
    command_args = [
        "scan",
        f"file:{dep_filepath}", # Correct f-string usage
        "--output", "cyclonedx-json", 
        "--enrich", "all",
        "--quiet"
    ]
    return _run_syft_command(command_args)

def process_docker_tar(tar_filepath):
    """Runs Syft on a Docker image tarball."""
    print(f"Processing Docker tar: {tar_filepath}")
    command_args = [
        "scan",
        f"docker-archive:{tar_filepath}", 
        "--output", "cyclonedx-json",
        "--enrich", "all",
        "--quiet"
    ]
    return _run_syft_command(command_args)

def process_existing_sbom(json_filepath):
    try:
        if json_filepath.endswith('.xml'):
            print(f"Processing XML SBOM file: {json_filepath} converting to JSON")
            data = _run_syft_command(["convert", json_filepath, "--output", "cyclonedx-json"])
        else:
            with open(json_filepath, 'r') as file:
                data = file.read()
        getdata = json.loads(data)
        get_format = getdata.get('bomFormat', '')
        if get_format != 'CycloneDX':
            raise ValueError("Uploaded file is not a valid CycloneDX SBOM format.")
        else:
            return json.loads(data)  
    except ValueError as e:
        raise ValueError(f"Uploaded file is not a valid SBOM: {e}")


def process_uploaded_file(filepath, upload_type):
    print(f"Dispatching processing for type '{upload_type}' and file '{filepath}'")
    if upload_type == 'zip_project':
        return process_zip_project(filepath)
    elif upload_type == 'dependency_file':
        return process_dependency_file(filepath)
    elif upload_type == 'docker_tar':
        return process_docker_tar(filepath)
    elif upload_type == 'existing_sbom_json':
        return process_existing_sbom(filepath)
    else:
        raise ValueError(f"Unsupported upload type: {upload_type}")

def osv_fetch_vul(comp_data):
    vuln_dict = []
    property_info = {}
    try:    
        print("Fetching vulnerabilities from OSV.dev...")
        osv_query_batch_url = "https://api.osv.dev/v1/querybatch"
        osv_vuln_detail_url = "https://api.osv.dev/v1/vulns/"
        t_comp_map = {}
        quries = []
        comp_map = {}
        for i, component in enumerate(comp_data):
            t_purl = component.get('purl').split('@')[0]
            purl = component.get('purl')
            comp_map[purl] = i
            t_comp_map[t_purl] = i
            if purl:
                quries.append({"package": {"purl": purl}})
        if not quries:
            print("No PURL found!!!")
            return comp_data, {
                "labels": ['Critical', 'High', 'Medium', 'Low'],
                "data": [0, 0, 0, 0, 0]
            }
        payload = {"queries": quries}
        vul_count = Counter({
        'CRITICAL': 0, 'HIGH': 0, 'MODERATE': 0, 'LOW': 0,
        })

        print(comp_data)
        
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from OSV: {e}")
        return comp_data, {
            "labels": ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            "data": [0, 0, 0, 0, 0]
        }
    except Exception as e:
        print(f"Something went wrong: {e}")
        return comp_data, {
            "labels": ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            "data": [0, 0, 0, 0, 0]
        }
    try:
        response = requests.post(osv_query_batch_url, json=payload, timeout=60)
        osv_result = response.json()
        index = [i for i, r in enumerate(osv_result['results']) if 'vulns' in r]
        s_dict = {key: [] for key in index}
        new_index = []
        # print(s_dict)            
        vul_ids = [vuln['id'] for i in index for vuln in osv_result['results'][i]['vulns']]
        unique_ids = set(vul_ids)  # Ensure unique IDs
        cve_id= set()
        number_8 = []
        # print(osv_result)
        print(f"Unique vulnerability IDs: {unique_ids}")
        cvs_name = ''
        for id in unique_ids:
            response = requests.get(f"{osv_vuln_detail_url}{id}", timeout=60)
            vuln_detail = response.json()
            db_specific = vuln_detail.get('database_specific', {})
            osv_severity = db_specific.get('severity', [])
            affected = vuln_detail.get('affected', [])
            github_reviewed = db_specific.get('github_reviewed', None)
            details = vuln_detail.get('details',[])
            cvs_severity = vuln_detail.get('severity',[])
            # cvs_score = cvs_severity[0]['score']
            cve_list = vuln_detail.get('aliases', [])
            cve = next((cve for cve in cve_list if cve.startswith('CVE-')), None)
            
            if github_reviewed is None or not github_reviewed:
                print(f"No severity found for vulnerability ID {id}. Skipping.")
                continue
            
            if not affected:
                print(f"No affected packages found for vulnerability ID {id}. Skipping.")
                continue

            # if not cvs_score:
            #     continue:
            print('\n\n',cvs_severity)
            if cvs_severity:
                if len(cvs_severity) == 2:
                    if cvs_severity[1]['type'] == 'CVSS_V4':
                        cvs_name = cvs_severity[1]['type'] 
                        cvs_score = cvs_severity[1]['score']    
                else:
                    cvs_name = cvs_severity[0]['type'] 
                    cvs_score = cvs_severity[0]['score']
            else:
                cvs_name = None
                cvs_score = None
                
            new_index.append(id)
            purl = affected[0]['package']['purl']
            if purl and purl in t_comp_map:
                i = t_comp_map[purl]
                if i in s_dict:
                    s_dict[i].append(osv_severity) 
                    # print(s_dict)
            severity = db_specific.get('severity')
            # print(f"Processing vulnerability ID {id} with severity {severity} and github_reviewed_at {github_reviewed_at}")

            if severity:
                severity = severity.upper()
                print(f"Found severity '{severity}' for vulnerability ID {id} for cve {cve} for the purl {affected[0]['package']['name']} with cvss score {cvs_score} ")

                property_info = {
                    "vul_id": id,
                    "cve": cve,
                    "severity": severity,
                    "name": affected[0]['package']['name'],
                    "details":details,
                    cvs_name:cvs_score,
                }
                vuln_dict.append(property_info)
                vul_count[severity] += 1
                # print(vuln_dict)
            else:
                # vul_count['NONE'] += 1
                pass
        reviewed_code = set(new_index)
        for i in index:
            reviewed_count = sum(1 for vuln in osv_result['results'][i]['vulns'] if vuln['id'] in reviewed_code)
            comp_data[i]["vulnerabilities"] = reviewed_count
        cleaned_dict = {k: [item for item in v if item != []] for k, v in s_dict.items()}
        for i in range(len(comp_data)):
            if i in s_dict and s_dict[i]:
                comp_data[i]["severities"] = cleaned_dict[i]
            else:
                comp_data[i]["severities"] = 'NONE'
        print(number_8)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from OSV: {e}")
        return comp_data, {
            "labels": ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            "data": [0, 0, 0, 0, 0]
        }
    except Exception as e:
        print(f"Something went wrong: {e}")
        return comp_data, {
            "labels": ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            "data": [0, 0, 0, 0, 0]
        }
    vulnerability_chart_data = {
        "labels": ['Critical', 'High', 'Medium', 'Low'],
        "data": [
            vul_count['CRITICAL'],
            vul_count['HIGH'],
            vul_count['MODERATE'],
            vul_count['LOW'],
            # vul_count['NONE']
        ]
    }
    return comp_data, vulnerability_chart_data, vuln_dict

def process_cyclonedx_sbom_data(raw_sbom_dict):
    # print(raw_sbom_dict)
    if not isinstance(raw_sbom_dict, dict):
        raise TypeError(f"Expected raw_sbom_dict to be a dictionary, but got {type(raw_sbom_dict)}")
    
    if not (raw_sbom_dict.get('bomFormat') == 'CycloneDX' and
           'specVersion' in raw_sbom_dict):
        #    isinstance(raw_sbom_dict['component'], list)):
       raise ValueError("Uploaded file is not a valid CycloneDX SBOM format. Missing 'bomFormat', 'specVersion', or 'components' array.")

    # if (raw_sbom_dict.get('sbomJsonParse')):
    #     raw_sbom_dict = raw_sbom_dict('sbomJsonParse', {})
    #     json.loads(raw_sbom_dict)

    unique_components_by_purl = {} 
    for component in raw_sbom_dict.get('components', []):
        purl = component.get('purl')
        name = component.get('name', 'N/A')
        version = component.get('version', 'N/A')

        unique_key = purl if purl and purl != 'N/A' else f"{name}@{version}"
        
        if unique_key not in unique_components_by_purl:
            unique_components_by_purl[unique_key] = component

    all_purl_unique_components = list(unique_components_by_purl.values())

    components_for_table = [] # This will be the final list for the dashboard table
    license_counts = Counter()
    
    TOOLING_PACKAGES = {'pip', 'setuptools', 'wheel', 'python','window-kill'}

    processed_component_by_bom_ref = {} 

    for component in all_purl_unique_components: # Iterate over the PURL-unique components
        name = component.get('name', 'N/A')
        version = component.get('version', 'N/A')
        component_type = component.get('type', 'N/A')
        purl = component.get('purl', 'N/A')
        component_ref = component.get('bom-ref') # Get bom-ref for graph building

        is_file_type = component_type == 'file'
        is_main_version = version == 'main'
        is_tooling_package = name.lower() in TOOLING_PACKAGES

        if not is_file_type and not is_main_version and not is_tooling_package:
            licenses = []
            if 'licenses' in component and isinstance(component['licenses'], list):
                for license_obj in component['licenses']:
                    if 'license' in license_obj and isinstance(license_obj['license'], dict):
                        if 'id' in license_obj['license']:
                            licenses.append(license_obj['license']['id'])
                        elif 'name' in license_obj['license']:
                            licenses.append(license_obj['license']['name'])
            license_string = ", ".join(licenses) if licenses else "No License Detected"
            
            if not licenses:
                license_counts["No License Detected"] += 1
            else:
                for lic in licenses:
                    license_counts[lic] += 1

            processed_entry = {
                "name": name,
                "version": version,
                "type": component_type, 
                "license": license_string,
                "vulnerabilities": "", 
                "severities": [],      
                "supplier": "",        
                "purl": purl,
                "bom-ref": component_ref # Keep bom-ref for internal mapping
            }
            components_for_table.append(processed_entry)
            
            
            
            if component_ref:
                processed_component_by_bom_ref[component_ref] = processed_entry
    
    adj_list = defaultdict(list) 
    all_component_refs_in_processed_list = set(processed_component_by_bom_ref.keys()) 
    is_dependent_of_anything = set() 

    for dep_entry in raw_sbom_dict.get('dependencies', []):
        source_ref = dep_entry.get('ref')
        if source_ref and source_ref in all_component_refs_in_processed_list: 
            for target_ref in dep_entry.get('dependsOn', []):
    
                if target_ref and target_ref in all_component_refs_in_processed_list: 
                    adj_list[source_ref].append(target_ref)
                    is_dependent_of_anything.add(target_ref)

    root_nodes = [ref for ref in all_component_refs_in_processed_list if ref not in is_dependent_of_anything]
    
    main_component_ref = raw_sbom_dict.get('metadata', {}).get('component', {}).get('bom-ref')
    if main_component_ref and main_component_ref in all_component_refs_in_processed_list and main_component_ref not in root_nodes:
        root_nodes.insert(0, main_component_ref) 
        
    if not root_nodes and all_component_refs_in_processed_list:
        root_nodes = list(all_component_refs_in_processed_list)

    # Calculate depths using BFS
    depths = {}
    q = deque()

    for root in root_nodes:
        if root not in depths: 
            depths[root] = 0
            q.append((root, 0))

    while q:
        current_node, current_depth = q.popleft()
        for neighbor in adj_list[current_node]: 
            if neighbor not in depths or current_depth + 1 < depths[neighbor]:
                depths[neighbor] = current_depth + 1
                q.append((neighbor, current_depth + 1))

    chart_depth_counts = Counter()
    for component_data_entry in components_for_table: 
        comp_ref = component_data_entry.get('bom-ref')
        if comp_ref and comp_ref in depths:
            calculated_depth = depths[comp_ref]
            chart_depth = calculated_depth + 1 
            
            if chart_depth >= 4:
                chart_depth_counts['Depth 4+'] += 1
            else:
                chart_depth_counts[f'Depth {chart_depth}'] += 1
        elif comp_ref and comp_ref not in depths:
            chart_depth_counts['Depth 1'] += 1 

    dependency_labels = ['Depth 1', 'Depth 2', 'Depth 3', 'Depth 4+']
    dependency_data = [chart_depth_counts[label] for label in dependency_labels]

    dependency_chart_data = {
        "labels": dependency_labels,
        "data": dependency_data
    }
    
    license_chart_data = {
        "labels": list(license_counts.keys()),
        "data": list(license_counts.values())
    }

    vulnerability_chart_data = {
        "labels": ['Critical', 'High', 'Medium', 'Low'],
        "data": [0, 0, 0, 0],
        "total_modules_found": 0, 
        "total_vulnerable_packages_found": 0 
    }
    
    return components_for_table, license_chart_data, vulnerability_chart_data, dependency_chart_data

def perform_full_sbom_analysis(file_path, upload_type, project_name, user_id, socketio_instance, db_instance, app_instance):
    print(f"Background task started for user {user_id}, project '{project_name}'.")
    raw_sbom_dict = None
    try:
        raw_sbom_dict = process_uploaded_file(file_path, upload_type)
        
        if raw_sbom_dict is None:
            raise ValueError("SBOM processing returned empty data (raw_sbom_dict is None).")

        components, license_data, vulnerability_chart_data, dependency_chart_data = \
            process_cyclonedx_sbom_data(raw_sbom_dict)

        components_for_table , vulnerability_chart_data,vuln_info = osv_fetch_vul(components)
        print("File_Path = ",file_path)
        graphData = cp.export_graph_data(file_path)
        with app_instance.app_context():
            from app import SBOM, VulnerabilityTable
            new_sbom_entry = SBOM(
                user_id=user_id,
                project_name=project_name,
                sbom_type=upload_type,
                raw_sbom_json=raw_sbom_dict,
                components_for_table=components_for_table,
                license_chart_data=license_data,
                vulnerability_chart_data=vulnerability_chart_data,
                dependency_chart_data=dependency_chart_data
            )
            db_instance.session.add(new_sbom_entry)
            db_instance.session.commit()
            print(f"Background task: New SBOM (ID: {new_sbom_entry.id}) committed successfully for user {user_id}.")
            user_room_id = str(user_id)
            socketio_instance.emit('new_sbom_available', {'sbom_id': new_sbom_entry.id, 'user_id': user_id}, room=user_room_id)
            print(f"Background task: Emitted 'new_sbom_available' to room {user_room_id}.")
            new_vuln_entry = VulnerabilityTable(
                id=new_sbom_entry.id,
                userID=user_id,
                vulnDetails=vuln_info,
                graphData=graphData
            )
            db_instance.session.add(new_vuln_entry)
            db_instance.session.commit()
        # 4. Emit SocketIO event to notify frontend (requires socketio instance)

    except Exception as e:
        print(f"Background task: Error processing SBOM for user {user_id}, project '{project_name}': {e}")
        with app_instance.app_context():
            db_instance.session.rollback()
        socketio_instance.emit('sbom_processing_error', {'message': f"Error processing SBOM: {str(e)}", 'user_id': user_id}, room=str(user_id))
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Background task: Cleaned up temporary file: {file_path}")
        # pass
        

