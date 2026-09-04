import os
import pandas as pd
from utils.cwe_find import CWEProcessor
from utils.diff_analyzer_legacy import analyze_code_diff

def transform_cwe_to_highest_parent(
    input_csv_path: str,
    output_csv_path: str,
    cwe_column_name: str = 'CWE_ID',
    new_parent_column_name: str = 'CWE_Parent'
):
    PREDEFINED_CWES_LIST = sorted([
        "CWE-189", "CWE-254", "CWE-264", "CWE-284", "CWE-310",
        "CWE-399", "CWE-664", "CWE-682", "CWE-691", "CWE-703", "CWE-707"
    ])

    try:


        processor = CWEProcessor()
    except FileNotFoundError as e:
        print(f"Error initializing CWEProcessor: {e}")
        print("Please ensure 'utils/assets/cwe_info_1000.csv' is accessible.")
        return
    except Exception as e:
        print(f"An unexpected error occurred during CWEProcessor initialization: {e}")
        return

    try:

        df = pd.read_csv(input_csv_path)
    except FileNotFoundError:
        print(f"Error: Input CSV file not found at {input_csv_path}")
        return
    except Exception as e:
        print(f"Error reading CSV file {input_csv_path}: {e}")
        return

    if cwe_column_name not in df.columns:
        print(f"Error: CWE column '{cwe_column_name}' not found in the input CSV.")
        print(f"Available columns are: {df.columns.tolist()}")
        return

    def get_highest_parent(cwe_id):
        if pd.isna(cwe_id) or not isinstance(cwe_id, str) or cwe_id.strip() == "":
            return None


        _ancestry_path, highest_parent = processor.process_cwe(str(cwe_id).strip())

        if highest_parent not in PREDEFINED_CWES_LIST:
            return 'CWE-0'
        return highest_parent


    try:
        df[new_parent_column_name] = df[cwe_column_name].apply(get_highest_parent)

        df.to_csv(output_csv_path, index=False)
        print(f"Processing complete. Output saved to {output_csv_path}")
    except Exception as e:
        print(f"Error during processing or saving the CSV: {e}")

def split_csv_by_cwe_parent(
    input_processed_csv_path: str,
    dataset_name: str,
    parent_cwe_column_name: str = 'CWE_Parent',
    output_base_dir: str = 'datasets'
):
    try:
        df = pd.read_csv(input_processed_csv_path)
    except FileNotFoundError:
        print(f"Error: Input CSV file not found at {input_processed_csv_path}")
        return
    except Exception as e:
        print(f"Error reading CSV file {input_processed_csv_path}: {e}")
        return

    if parent_cwe_column_name not in df.columns:
        print(f"Error: Parent CWE column '{parent_cwe_column_name}' not found in the input CSV.")
        print(f"Available columns are: {df.columns.tolist()}")
        return

    output_path = os.path.join(output_base_dir, dataset_name, 'cwe_split')
    os.makedirs(output_path, exist_ok=True)
    print(f"Output directory created/ensured: {output_path}")

    unique_parent_cwes = df[parent_cwe_column_name].unique()

    for parent_cwe in unique_parent_cwes:
        if pd.isna(parent_cwe):
            print(f"Skipping NaN parent CWE value.")
            continue


        safe_parent_cwe_filename = str(parent_cwe).replace('/', '_').replace('\\', '_')

        sub_df = df[df[parent_cwe_column_name] == parent_cwe]
        output_filename = f"{safe_parent_cwe_filename}.csv"
        full_output_path = os.path.join(output_path, output_filename)

        try:
            sub_df.to_csv(full_output_path, index=False)
            print(f"Successfully saved: {full_output_path} ({len(sub_df)} rows)")
        except Exception as e:
            print(f"Error saving file {full_output_path}: {e}")

    print(f"CSV splitting process complete for {input_processed_csv_path}.")

def add_headers_and_ids_to_csv(
    input_csv_path: str,
    output_csv_path: str,
    headers: list = ['code_before', 'code_after', 'cwe_type', 'cve_id'],
    id_column_name: str = 'id',
    id_prefix: str = ''
):
    try:

        df = pd.read_csv(input_csv_path)

        target_headers = headers.copy()
        num_target_headers = len(target_headers)


        if len(df.columns) > num_target_headers:
            df = df.iloc[:, :num_target_headers]


        df.columns = target_headers[:len(df.columns)]


        if len(df.columns) < num_target_headers:
            for i in range(len(df.columns), num_target_headers):
                df[target_headers[i]] = pd.NA


        df.insert(0, id_column_name, [i for i in range(len(df))])


        df.to_csv(output_csv_path, index=False)
        print(f"Processing complete. Added headers and ID column, output saved to {output_csv_path}")
        print(f"Total rows: {len(df)}")
        print(f"Final column names: {list(df.columns)}")

    except FileNotFoundError:
        print(f"Error: Input CSV file not found: {input_csv_path}")
    except Exception as e:
        print(f"Error processing CSV file: {e}")

if __name__ == '__main__':

    INPUT_CSV = 'test_input.csv'
    OUTPUT_CSV_PROCESSED = 'test_output_with_parents.csv'
    DATASET_NAME_FOR_SPLIT = 'my_test_dataset'

    try:
        pd.DataFrame({
            'CWE_ID': ['CWE-119', 'CWE-20', 'CWE-79', 'CWE-190', 'CWE-12345', None, 'CWE-664', 'CWE-22', 'CWE-416', 'CWE-787'],
            'Other_Data': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        }).to_csv(INPUT_CSV, index=False)

        print(f"Created dummy '{INPUT_CSV}' for demonstration.")

        transform_cwe_to_highest_parent(INPUT_CSV, OUTPUT_CSV_PROCESSED, cwe_column_name='CWE_ID')

        print(f"\nFinished processing '{INPUT_CSV}' to '{OUTPUT_CSV_PROCESSED}'.")


        print(f"\nStarting CSV split for '{OUTPUT_CSV_PROCESSED}'...")

        if os.path.exists(OUTPUT_CSV_PROCESSED):
            split_csv_by_cwe_parent(
                input_processed_csv_path=OUTPUT_CSV_PROCESSED,
                dataset_name=DATASET_NAME_FOR_SPLIT,
                parent_cwe_column_name='CWE_Parent'
            )
            print(f"Splitting complete. Check the '{os.path.join('datasets', DATASET_NAME_FOR_SPLIT, 'cwe_split')}' directory.")
        else:
            print(f"Error: Processed file '{OUTPUT_CSV_PROCESSED}' not found. Skipping split example.")

    except Exception as e:
        print(f"Error in example usage: {e}")
