import os
import pandas as pd

class Analyzer:
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir

    def read_all_patients_data(self):
        patients_data = {}

        csv_files = [f for f in os.listdir(self.data_dir) if f.endswith(".csv")]

        for file_path in csv_files:
            try:
                patient_id = file_path.split("_")[1].replace(".csv", "")
                df = pd.read_csv(os.path.join(self.data_dir, file_path))
                patients_data[patient_id] = df
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")

        if not patients_data:
            print("No patients data found")
            return None

        return patients_data

    def analyze_individual_patient_data(self, patients_data):
        patient_averages = {}

        for patient_id, df in patients_data.items():
            avg_systolic = df["systolic"].mean()
            avg_diastolic = df["diastolic"].mean()
            avg_heart_rate = df["heart_rate"].mean()

            patient_averages[patient_id] = {
                "avg_systolic": avg_systolic,
                "avg_diastolic": avg_diastolic,
                "avg_heart_rate": avg_heart_rate,
            }

        return patient_averages

    def analyze_all_patients_data(self, patients_data):
        all_data = pd.concat(patients_data.values(), ignore_index=True)

        averages = {}
        averages["avg_systolic"] = all_data["systolic"].mean()
        averages["avg_diastolic"] = all_data["diastolic"].mean()
        averages["avg_heart_rate"] = all_data["heart_rate"].mean()

        return averages
    
    def print_results(self):
        patients_data = self.read_all_patients_data()

        if not patients_data:
            print("No patients data found")
            return
        
        print(f"Total number of patients: {len(patients_data)}")

        print("\nINDIVIDUAL PATIENTS AVERAGES")
        print("-" * 30)
        patient_averages = self.analyze_individual_patient_data(patients_data)

        for patient_id in sorted(patient_averages.keys()):
            avg = patient_averages[patient_id]
            print(f"Patient {patient_id}:")
            print(f"Average systolic: {avg['avg_systolic']:.2f}")
            print(f"Average diastolic: {avg['avg_diastolic']:.2f}")
            print(f"Average heart rate: {avg['avg_heart_rate']:.2f}\n")

        overall_averages = self.analyze_all_patients_data(patients_data)
        print("\nOVERALL AVERAGES")
        print("-" * 30)
        print(f"Average systolic: {overall_averages['avg_systolic']:.2f}")
        print(f"Average diastolic: {overall_averages['avg_diastolic']:.2f}")
        print(f"Average heart rate: {overall_averages['avg_heart_rate']:.2f}")
            
            
        
if __name__ == "__main__":
    analyzer = Analyzer()
    analyzer.print_results()



