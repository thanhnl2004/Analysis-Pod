from datetime import datetime
import pandas as pd
import sys
import os
import glob
from dotenv import load_dotenv

from decrypt import (
    gen_master_key, 
    decrypt_patient_file,
    NUM_OF_PATIENTS
)

load_dotenv()

BASE_DIR = "/opt/solid"

class Analyzer:
    def __init__(self, base_dir):
        self.base_dir = base_dir


    def get_all_ttl_files(self, patient_id):
        blood_pressure_dir = os.path.join(
            self.base_dir,
            "server",
            f"patient{patient_id}",
            "healthpod",
            "data",
            "blood_pressure"
        )
        if not os.path.exists(blood_pressure_dir):
            print(f"Directory not found: {blood_pressure_dir}")
            return {}
        
        ttl_files = glob.glob(os.path.join(blood_pressure_dir, "*.ttl"))

        return ttl_files

    def decrypt_all_patients_to_dataframes(self):
        """
        Decrypt all patient data and convert to pandas DataFrames.
        """
        # Get the security key
        security_key_str = os.getenv('SECURITY_KEY')
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
                patient_dir = os.path.join(
                    self.base_dir,
                    "server",
                    f"patient{patient_id}",
                )
                
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



