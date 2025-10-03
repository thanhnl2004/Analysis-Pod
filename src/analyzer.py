from datetime import datetime
import pandas as pd
import sys
import os
import glob
import json
from rdflib import Graph, URIRef, Namespace
from base64 import b64encode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad
from urllib.parse import urlparse

from decrypt import (
    gen_master_key, 
    decrypt_patient_file,
    NUM_OF_PATIENTS
)

BASE_DIR = "/opt/solid"

apps_terms = 'https://solidcommunity.au/predicates/terms#'
app_name = 'healthpod'
path_pred = 'path'
iv_pred = 'iv'
session_key_pred = 'sessionKey'
data_pred = 'encData'

class Analyser:
    def __init__(self, base_dir, security_key):
        self.base_dir = base_dir
        self.master_key = gen_master_key(security_key)


    def get_file_url(self, file_path, patient_id):
        """Generate file URL based on patient ID"""
        web_id = f'https://pods.test.solidcommunity.au/patient{patient_id:02d}/profile/card#me'
        return web_id.replace('profile/card#me', file_path)


    def encrypt(self, data_str, key, iv):
        """Encrypt data string using AES CTR mode"""
        assert len(iv) == 16
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8], initial_value=iv[8:])
        padded_data = pad(data_str.encode('utf-8'), AES.block_size)
        return b64encode(cipher.encrypt(padded_data)).decode('ascii')


    def upload_encrypted_file(self, json_data, destination_path, patient_id):
        """Save JSON data as encrypted .json.enc.ttl file"""
        if not self.master_key:
            raise ValueError("Master key not set. Call set_master_key() first.")

        # Convert JSON to string with proper indentation
        file_content = json.dumps(json_data, indent=4, ensure_ascii=False)

        # Encrypt file content
        session_key = get_random_bytes(32)
        data_iv = get_random_bytes(16)
        enc_data_b64 = self.encrypt(file_content, session_key, data_iv)

        # Get file URL and encode IV
        file_url = self.get_file_url(destination_path, patient_id)
        data_iv_b64 = b64encode(data_iv).decode('ascii')
        
        # Construct Turtle format
        ttl_content = f"""@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
            @prefix solidTerms: <{apps_terms}> .

            <{file_url}> solidTerms:{path_pred} "{destination_path}" ;
                solidTerms:{iv_pred} "{data_iv_b64}"^^xsd:string ;
                solidTerms:{data_pred} "{enc_data_b64}"^^xsd:string .
            """
        
        # Write encrypted data to file
        abs_path = os.path.join(self.patient_dir(patient_id), destination_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, 'w') as f:
            f.write(ttl_content)

        # Add session key to ind-keys.ttl
        self.add_session_key(destination_path, patient_id, session_key)


    def add_session_key(self, file_path, patient_id, session_key):
        """Add encrypted session key to ind-keys.ttl"""
        web_id = f'https://pods.test.solidcommunity.au/patient{patient_id:02d}/profile/card#me'
        uri = urlparse(web_id)
        server_url = f'https://{uri.netloc}/'
        pod_name = f'patient{patient_id:02d}'
        file_url = self.get_file_url(file_path, patient_id)

        # Encrypt the session key
        session_key_iv = get_random_bytes(16)
        session_key_b64 = b64encode(session_key).decode('ascii')
        enc_session_key_b64 = self.encrypt(session_key_b64, self.master_key, session_key_iv)

        # Parse the ind-keys.ttl file
        ind_key_path = os.path.join(self.patient_dir(patient_id), app_name, 'encryption', 'ind-keys.ttl')
        g = Graph()
        g.parse(ind_key_path)
        
        # Bind the namespace to use 'solidTerms' prefix
        solidTerms = Namespace(apps_terms)
        g.bind('solidTerms', solidTerms)

        # Replace file:///POD_DIR prefix with server URL
        for s, p, o in list(g):
            prefix = 'file:///opt/solid/server/'
            if str(s).startswith(prefix):
                new_s = str(s).replace(prefix, server_url)
                g.add((URIRef(new_s), p, o))
                g.remove((s, p, o))
            # Remove triple if the subject already exists
            if str(s) == file_url:
                g.remove((s, p, o))

        # Add encrypted session key to ind-keys.ttl
        session_key_iv_b64 = b64encode(session_key_iv).decode('ascii')
        query = f'INSERT DATA {{<{file_url}> <{apps_terms}{path_pred}> "{file_path}"; ' + \
                f'<{apps_terms}{iv_pred}> "{session_key_iv_b64}"; ' + \
                f'<{apps_terms}{session_key_pred}> "{enc_session_key_b64}".}};'
        g.update(query)

        # Write back ind-keys.ttl
        ttl_str = g.serialize(format='turtle', base=server_url)
        with open(ind_key_path, 'w') as f:
            f.write(ttl_str)


    def patient_dir(self, patient_id: int) -> str:
        pid = int(patient_id)
        return os.path.join(self.base_dir, "server", f"patient{pid:02d}")


    def get_all_ttl_files(self, patient_id):
        blood_pressure_dir = os.path.join(
            self.patient_dir(patient_id),
            "healthpod",
            "data",
            "blood_pressure"
        )
        if not os.path.exists(blood_pressure_dir):
            print(f"Directory not found: {blood_pressure_dir}")
            return {}
        
        ttl_files = glob.glob(os.path.join(blood_pressure_dir, "blood_pressure*.ttl"))

        return ttl_files


    def decrypt_all_patients(self):
        """
        Decrypt all patient data and convert to pandas DataFrames.
        """
        patient_dataframes = {}
        # Process patients 01 through NUM_OF_PATIENTS
        for patient_id in range(1, NUM_OF_PATIENTS + 1):
            blood_pressure_files = self.get_all_ttl_files(patient_id)

            patient_observations = []
            for blood_pressure_file in blood_pressure_files:
                filename = os.path.basename(blood_pressure_file)
                patient_dir = self.patient_dir(patient_id)
                observation = decrypt_patient_file(self.master_key, patient_dir, filename)
                
                if observation:
                    patient_observations.append(observation)
            
            if patient_observations:
                # Convert list of dictionaries to DataFrame 
                df = pd.DataFrame(patient_observations)
                
                # Convert timestamp to datetime
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                
                # Convert columns data to numeric
                numeric_columns = ['systolic', 'diastolic', 'heart_rate']
                for col in numeric_columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce')
                
                # Sort by timestamp
                df = df.sort_values('timestamp').reset_index(drop=True)
                
                # Add patient_id column for reference
                df['patient_id'] = patient_id
                
                patient_dataframes[patient_id] = df
                print(f'Created DataFrame for {patient_id}: {len(df)} observations')
            else:
                print(f'No data found for {patient_id}')
        
        print(f"\nSuccessfully created {len(patient_dataframes)} DataFrames")
        return patient_dataframes
    

    def generate_summary(self, patient_dfs, export_summaries=True, export_format='json'):
        if not patient_dfs:
            print("No patient dataframes provided; skipping statistics.")
            return pd.DataFrame()

        summary_stats = []
        for patient_id, df in patient_dfs.items():
            blood_pressure_dir = os.path.join(
                self.patient_dir(patient_id), 
                "healthpod", 
                "data", 
                "blood_pressure"
            )
            patient_json_data = {"patient id": int(patient_id)}
            descriptive_stats = {}
            numeric_cols = ['systolic', 'diastolic', 'heart_rate']

            for col in numeric_cols:
                if col in df.columns:
                    values = df[col].dropna()
                    if len(values) > 0:
                        descriptive_stats[col] = {
                            'count': int(len(values)),
                            'mean': round(float(values.mean()), 2),
                            'median': round(float(values.median()), 2),
                            'std': round(float(values.std()), 2),
                            'min': round(float(values.min()), 2),
                            'max': round(float(values.max()), 2),
                            'range': round(float(values.max() - values.min()), 2),
                            'percentile_25': round(float(values.quantile(0.25)), 2),
                            'percentile_75': round(float(values.quantile(0.75)), 2),
                        }

            patient_json_data['descriptive_statistics'] = descriptive_stats

            summary = {'patient_id': int(patient_id), 'total_observations': int(len(df))}
            if 'timestamp' in df.columns and df['timestamp'].notna().any():
                summary['date_range_days'] = int((df['timestamp'].max() - df['timestamp'].min()).days)
            for col in numeric_cols:
                if col in df.columns and df[col].notna().any():
                    v = df[col].dropna()
                    summary.update({
                        f'{col}_mean': float(v.mean()),
                        f'{col}_median': float(v.median()),
                        f'{col}_std': float(v.std()),
                        f'{col}_min': float(v.min()),
                        f'{col}_max': float(v.max()),
                        f'{col}_range': float(v.max() - v.min()),
                    })
            summary_stats.append(summary)
        summary_df = pd.DataFrame(summary_stats)

        # Create aggregated statistics across all patients (privacy-preserving)
        if export_summaries and export_format.lower() == 'json':
            # Combine all patient data for aggregated statistics
            all_data = pd.concat(patient_dfs.values(), ignore_index=True)
            
            numeric_cols = ['systolic', 'diastolic', 'heart_rate']
            aggregated_stats = {
                'total_patients': int(len(patient_dfs)),
                'total_observations': int(len(all_data)),
            }
            
            for col in numeric_cols:
                if col in all_data.columns:
                    values = all_data[col].dropna()
                    if len(values) > 0:
                        aggregated_stats[col] = {
                            'mean': round(float(values.mean()), 2),
                            'median': round(float(values.median()), 2),
                            'std': round(float(values.std()), 2),
                            'min': round(float(values.min()), 2),
                            'max': round(float(values.max()), 2),
                            'range': round(float(values.max() - values.min()), 2)
                        }
            
            # Save encrypted overall summary for each patient with their individual data
            for patient_id in range(1, NUM_OF_PATIENTS + 1):
                if patient_id in patient_dfs:
                    df = patient_dfs[patient_id]
                    patient_statistics = {
                        "patient_id": int(patient_id),
                        "total_observations": int(len(df)),
                    }
                    numeric_cols = ['systolic', 'diastolic', 'heart_rate']

                    for col in numeric_cols:
                        if col in df.columns:
                            values = df[col].dropna()
                            if len(values) > 0:
                                patient_statistics[col] = {
                                    'mean': round(float(values.mean()), 2),
                                    'median': round(float(values.median()), 2),
                                    'std': round(float(values.std()), 2),
                                    'min': round(float(values.min()), 2),
                                    'max': round(float(values.max()), 2),
                                    'range': round(float(values.max() - values.min()), 2),
                                }

                    overall_for_patient = {
                        "aggregated_statistics": aggregated_stats,
                        "patient_statistics": patient_statistics,
                    }
                    
                    destination_path = f'{app_name}/data/blood_pressure/overall_summary.json.enc.ttl'
                    self.upload_encrypted_file(overall_for_patient, destination_path, patient_id)
                    print(f"Saved encrypted aggregated summary for patient {patient_id:02d}")

        return summary_df


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 analyser.py <security_key>")
        sys.exit(1)

    security_key_str = sys.argv[1]
    analyser = Analyser(BASE_DIR, security_key_str)

    patient_dfs = analyser.decrypt_all_patients()
    summary_df = analyser.generate_summary(patient_dfs, export_summaries=True, export_format='json')
    print("\nSummary Statistics DataFrame:")
    print(summary_df)











