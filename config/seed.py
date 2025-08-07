import random
import pandas as pd
from datetime import datetime, timedelta
import csv

PATIENTS_COUNT = 10
OBSERVATIONS_COUNT = 20

categories = [
    ("Normal", (90, 119), (60, 79)),
    ("Elevated", (120, 129), (60, 79)),
    ("Stage1", (130, 139), (80, 89)),
    ("Stage2", (140, 180), (90, 120)),
    ("Crisis", (181, 200), (121, 140)),
]

# create a list of timestamps, starting from 1st August 2025, 8:00 AM
start = datetime(2025, 8, 1, 8)
timestamps = [(start + timedelta(days=i)).strftime("%Y-%m-%dT%H:%M:%SZ") for i in range(1, OBSERVATIONS_COUNT + 1)]

for patient_id in range(1, PATIENTS_COUNT + 1):
    rows = []

    # ensure each category appears at least once
    picks = list(range(len(categories)))
    # extends the list with random categories until the list length is OBSERVATIONS_COUNT (20)
    picks = list(range(len(categories))) + [random.randrange(len(categories)) for _ in range(OBSERVATIONS_COUNT - len(categories))]
    random.shuffle(picks)

    for index, cat_id in enumerate(picks):
        systolic_range = categories[cat_id][1]
        diastolic_range = categories[cat_id][2]

        # generate a random value for systolic, diastolic and heart rate
        systolic_value = random.randint(systolic_range[0], systolic_range[1])
        diastolic_value = random.randint(diastolic_range[0], diastolic_range[1])
        heart_rate_value = random.randint(60, 100)

        rows.append([
            timestamps[index],
            systolic_value,
            diastolic_value,
            heart_rate_value,
        ])

    # write the rows to each csv file
    filename = f"data/patient_{patient_id}_data.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "systolic", "diastolic", "heart_rate"])
        writer.writerows(rows)

    print(f"{filename}: Generated data for patient {patient_id}")
