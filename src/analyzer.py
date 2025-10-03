from datetime import datetime
import pandas as pd
import sys
import os
import glob
from dotenv import load_dotenv
import json

from decrypt import (
    gen_master_key, 
    decrypt_patient_file,
    NUM_OF_PATIENTS
)

load_dotenv()

BASE_DIR = "/opt/solid"

class Analyser:
    def __init__(self, base_dir):
        self.base_dir = base_dir

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

    def decrypt_all_patients_to_dataframes(self):
        """
        Decrypt all patient data and convert to pandas DataFrames.
        """
        # Get the security key
        security_key_str = "thanh20043005123"
        if not security_key_str:
            print("SECURITY_KEY not found in .env file!")
            return {}
        
        # Generate master key 
        master_key = gen_master_key(security_key_str)
        patient_dataframes = {}
        
        # Process patients 01 through NUM_OF_PATIENTS
        for patient_id in range(1, NUM_OF_PATIENTS + 1):
            blood_pressure_files = self.get_all_ttl_files(patient_id)

            patient_observations = []
            for blood_pressure_file in blood_pressure_files:
                filename = os.path.basename(blood_pressure_file)
                patient_dir = self.patient_dir(patient_id)
                observation = decrypt_patient_file(master_key, patient_dir, filename)
                
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
    
    def generate_patient_statistics(self, patient_dfs, export_summaries=True, export_format='json'):
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

            if export_summaries and export_format.lower() == 'json':
                os.makedirs(blood_pressure_dir, exist_ok=True)
                with open(os.path.join(blood_pressure_dir, f'{int(patient_id):02d}_summary.json'), 'w') as f:
                    json.dump(patient_json_data, f, indent=4, ensure_ascii=False)

        summary_df = pd.DataFrame(summary_stats)

        for patient_id in (1, NUM_OF_PATIENTS):
            if patient_id in patient_dfs and export_summaries and export_format.lower() == 'json':
                overall = {
                    "total_patients": len(patient_dfs),
                    "summary_statistics": summary_df.round(2).to_dict("records"),
                }
                with open(os.path.join(
                    self.patient_dir(patient_id), 
                    "healthpod", 
                    "data", 
                    "blood_pressure", 
                    "overall_summary.json"), 'w'
                    ) as f:
                    json.dump(overall, f, indent=4, ensure_ascii=False)

        return summary_df

if __name__ == "__main__":
    analyser = Analyser(BASE_DIR)
    patient_dfs = analyser.decrypt_all_patients_to_dataframes()
    summary_df = analyser.generate_patient_statistics(patient_dfs, export_summaries=True, export_format='json')
    print("\nSummary Statistics DataFrame:")
    print(summary_df)



       







