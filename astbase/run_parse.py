import logging
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
import os
import pickle
import sys
import traceback
from AST import GumTreeAstPair
import Pattern
from tqdm import tqdm
import logging
csv.field_size_limit(sys.maxsize)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
logging.getLogger("openai").setLevel(logging.ERROR)
logging.getLogger("httpx").setLevel(logging.ERROR)


def process_pair(i, pair, llm, language='c', slice=False):
    try:
        before = pair[0]
        after = pair[1]
        t = GumTreeAstPair(before=before, after=after, idx=i, language=language)

    except TimeoutError as e:
        logging.error(f"Timeout at pair {i}: {e}")
        return i, None, 'timeout'
    except KeyError as e:
        traceback.print_exc()
        logging.error(f"Parse error at pair {i}: {e}")
        return i, None, 'parse_err'
    except Exception as e:
        traceback.print_exc()
        logging.error(f"unknown error at pair {i}: {e}")
        return i, None, 'unknown_err'

    try:
        if not llm:
            patterns = Pattern.getEditPatterns(i, t, llm=llm)
        else:
            patterns = Pattern.getEditPatterns(i, t, llm=llm, slice_context=pair[3], domain=pair[4], functionality=pair[5], before_condition=pair[6],
                                               after_condition=pair[7], before_condition_formula=pair[8], after_condition_formula=pair[9], premises=pair[10])
    except KeyError as e:
        traceback.print_exc()
        logging.error(f"Pattern error at pair {i}: {e}")
        return i, None, 'pattern_err'
    except Exception as e:
        traceback.print_exc()
        logging.error(f"unknown error at pair {i}: {e}")
        return i, None, 'unknown_err'

    return i, t, patterns


def parse(dataset_path, project_name, end_point, llm, language, slice):
    parsed_data = {}
    successful_pairs = 0
    with open(dataset_path, 'r') as file:
        pairs = list(csv.reader(file))

    with ProcessPoolExecutor(max_workers=os.cpu_count()-1) as executor:
        futures = []
        for i, pair in enumerate(pairs):
            if i > end_point:
                break
            futures.append(executor.submit(process_pair, i, pair, llm, language, slice))
            print(f"Processing pair {i}")

        for future in tqdm(as_completed(futures), total=len(futures)):
            try:
                i, t, patterns = future.result()
                if patterns not in ['timeout', 'parse_err', 'pattern_err', 'unknown_err'] and t is not None:
                    parsed_data[i] = [t, patterns]
                    if patterns and len(patterns) > 0:
                        successful_pairs += 1
            except Exception as exc:
                logging.error(f"Error occurred while storing pair: {exc}")

    print('Total pairs processed:', len(futures))
    print('Pairs with successfully extracted patterns:', successful_pairs)
    print('Success rate:', f"{successful_pairs/len(futures):.2%}" if len(futures) > 0 else "0%")
    print('Pairs saved to parsed_data:', len(parsed_data))

    output_file = os.path.join('../datasets/', project_name, f"{project_name}_{end_point}.pkl")
    with open(output_file, "wb") as fdata:
        pickle.dump(parsed_data, fdata)
    logging.info(f"Data saved to {output_file}")


if __name__ == '__main__':
    llm = False
    slice_flag = False
    project_name = 'ICVul'
    end_point = 10000
    dataset_path = '../datasets/ICVul/processed_vulnerabilities.csv'
    parse(dataset_path, project_name, end_point, llm, 'c', slice_flag)
