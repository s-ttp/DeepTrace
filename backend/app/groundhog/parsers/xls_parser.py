"""
XLS/XLSX parser for Groundhog radio traces.

Supports multiple sheets with automatic detection of the data sheet.
"""
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Known column names that indicate a Groundhog data sheet
GROUNDHOG_INDICATORS = [
    "time", "timestamp", "event", "type", "rsrp", "rsrq", "sinr",
    "cell", "pci", "earfcn", "procedure", "message", "datetime",
    "imsi", "ue", "handover", "rlf", "paging", "rat",
]


def parse_xls(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse an XLS or XLSX file containing Groundhog radio trace data.
    
    Features:
    - Auto-detect the correct sheet by column headers
    - Support both .xls (xlrd) and .xlsx (openpyxl) formats
    
    Returns:
        List of dicts, one per row
    """
    import pandas as pd
    
    # Determine engine based on extension
    ext = file_path.lower().split(".")[-1]
    if ext == "xls":
        engine = "xlrd"
    else:
        engine = "openpyxl"
    
    try:
        # Read all sheet names first
        xl = pd.ExcelFile(file_path, engine=engine)
        sheet_names = xl.sheet_names
        logger.info(f"Excel file has {len(sheet_names)} sheets: {sheet_names}")
        
        if len(sheet_names) == 1:
            # Only one sheet, use it
            df = pd.read_excel(file_path, engine=engine, dtype=str, na_filter=False)
        else:
            # Multiple sheets - find best match
            best_sheet = None
            best_score = 0
            
            for sheet_name in sheet_names:
                try:
                    df_sample = pd.read_excel(
                        file_path, sheet_name=sheet_name,
                        engine=engine, nrows=5, dtype=str, na_filter=False
                    )
                    columns_lower = [str(c).lower().strip() for c in df_sample.columns]
                    score = sum(1 for ind in GROUNDHOG_INDICATORS if any(ind in col for col in columns_lower))
                    
                    # Also consider row count
                    if score > best_score or (score == best_score and len(df_sample) > 0):
                        best_score = score
                        best_sheet = sheet_name
                except Exception:
                    continue
            
            if best_sheet is None:
                best_sheet = sheet_names[0]
            
            logger.info(f"Selected sheet '{best_sheet}' (score: {best_score})")
            df = pd.read_excel(
                file_path, sheet_name=best_sheet,
                engine=engine, dtype=str, na_filter=False
            )
        
        # Clean column names
        df.columns = [str(col).strip() for col in df.columns]
        
        result = df.to_dict(orient="records")
        logger.info(f"Parsed {len(result)} rows from Excel with {len(df.columns)} columns")
        return result
        
    except Exception as e:
        logger.error(f"Excel parse failed: {e}")
        raise ValueError(f"Failed to parse Excel file: {e}")
