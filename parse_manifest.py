#!/usr/bin/env python3

# Imports
import xml.etree.ElementTree as ET
import csv
import os
import shutil
import subprocess
from distutils.dir_util import copy_tree
import fnmatch
import pandas as pd
import glob

# Constants
TARGET_DIR = "/Users/vlopes/Desktop/python-scripts/commit-builder/parsed-juliet"
TESTCASE_SUPPORT_DIR = "/Users/vlopes/Desktop/Java/src/testcasesupport"
LIB_DIR = "/Users/vlopes/Desktop/Java/lib"
JULIET_DS = "/Users/vlopes/Desktop/Java/"
CSV_FILE = "juliet_selected_samples.csv"  # Your uploaded CSV

def create_directory(count):  
    """Create directory structure for each testcase"""
    dir_name = f"testcase-{count}"
    path = os.path.join(TARGET_DIR, dir_name).replace("\\","/")
    
    if not os.path.isdir(path):
        print(f"📁 Creating {path}")
        os.mkdir(path) 

        # Create lib and testcasesupport directories
        lib_path = path + "/lib"
        os.mkdir(lib_path)
        testcasesupport_path = path + "/testcasesupport"
        os.mkdir(testcasesupport_path)
        copy_dir_contents(LIB_DIR, lib_path)
        copy_dir_contents(TESTCASE_SUPPORT_DIR, testcasesupport_path)
        
        new_path = path + "/testcases"
        os.mkdir(new_path)
        return new_path

def create_nested_directory(dir_path):
    """Create nested directories within testcase folders"""
    if not os.path.isdir(dir_path):
        path = os.path.join(dir_path).replace("\\","/")
        os.mkdir(path)
        return path

def copy_file(src_file_path, dest_path):
    """Copy specific file into destination directory"""
    print(f"📄 Copying: {os.path.basename(src_file_path)}")
    shutil.copy(src_file_path, dest_path) 

def copy_dir_contents(src_dir, dest_dir):
    """Copy entire contents of directory into destination directory"""
    copy_tree(src_dir, dest_dir)

def find_file(root_dir, filename):
    """Search for file within Juliet dataset folder structure"""
    print(f"🔍 Searching for: {filename}")
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file == filename:  # Exact match instead of fnmatch
                file_path = os.path.join(root, file)
                print(f"✅ Found: {file_path}")
                return file_path
    print(f"❌ Not found: {filename}")
    return None

def extract_filename_from_csv_path(csv_path):
    """Extract just the filename from the CSV path"""
    # CSV path format: testcases/testcase-X/src/main/java/testcases/CWEXXX_Name/subdir/filename.java
    # We want: filename.java
    return os.path.basename(csv_path)

def read_csv_targets():
    """Read CSV file and extract all target filenames"""
    print(f"📊 Reading CSV file: {CSV_FILE}")
    
    try:
        df = pd.read_csv(CSV_FILE)
        print(f"✅ Loaded {len(df)} rows from CSV")
        
        # Extract just the filenames from the full paths
        df['filename'] = df['file_path'].apply(extract_filename_from_csv_path)
        
        # Get unique filenames (remove duplicates from multiple tainted lines)
        unique_files = df['filename'].unique()
        print(f"📁 Unique files to process: {len(unique_files)}")
        
        # Show CWE distribution for info
        cwe_counts = df['cwe_id'].value_counts().sort_index()
        print(f"📊 CWE distribution in CSV:")
        for cwe, count in cwe_counts.items():
            print(f"   CWE-{cwe}: {count} samples")
        
        return unique_files.tolist()
        
    except FileNotFoundError:
        print(f"❌ CSV file not found: {CSV_FILE}")
        return []
    except Exception as e:
        print(f"❌ Error reading CSV: {e}")
        return []

def parse_manifest_for_testcase(target_file):
    """Find the complete testcase structure for a target file in manifest.xml"""
    print(f"🔍 Looking for '{target_file}' in manifest.xml")
    
    try:
        # Try lxml first, fallback to ElementTree
        try:
            from lxml import etree
            parser = etree.XMLParser(recover=True)
            tree = etree.parse('manifest.xml', parser)
            root = tree.getroot()
            print("✅ Parsed manifest.xml with lxml")
        except ImportError:
            tree = ET.parse('manifest.xml')
            root = tree.getroot()
            print("✅ Parsed manifest.xml with ElementTree")
            
        # Find testcase containing our target file
        testcases_found = 0
        for testcase in root.findall("testcase"):
            testcases_found += 1
            files_in_testcase = []
            target_found = False
            
            for file_elem in testcase:
                file_path = file_elem.get("path")
                if file_path:  # Make sure path attribute exists
                    files_in_testcase.append(file_path)
                    
                    # Check if this is our target file (exact match)
                    if file_path == target_file:
                        target_found = True
                        print(f"🎯 Found '{target_file}' in testcase with {len(files_in_testcase)} total files")
            
            if target_found:
                print(f"📁 Complete testcase files:")
                for f in files_in_testcase:
                    print(f"   - {f}")
                return files_in_testcase
        
        print(f"📊 Searched {testcases_found} testcases in manifest")
        print(f"❌ Target file '{target_file}' not found in any testcase")
        return [target_file]  # Fallback to just the target file
                
    except Exception as e:
        print(f"❌ Error parsing manifest for {target_file}: {e}")
        return [target_file]  # Fallback to just the target file

def get_directory_structure_from_file(file_path):
    """Extract directory structure from file path"""
    # Find actual file in Juliet dataset
    actual_path = find_file(JULIET_DS, file_path)
    if actual_path:
        trim_idx = actual_path.rfind('testcases') + 10
        trimmed_path = actual_path[trim_idx:].replace("\\","/")
        return trimmed_path.split("/")[:-1]  # Remove filename, keep directory structure
    return []

def compile_java_files(testcase_dir, testcase_count):
    """Compile all Java files in the testcase directory"""
    print(f"🔨 Compiling Java files for testcase-{testcase_count}")
    
    # Paths
    testcases_path = os.path.join(testcase_dir, "testcases")
    testcasesupport_path = os.path.join(testcase_dir, "testcasesupport")
    lib_path = os.path.join(testcase_dir, "lib")
    
    # Find all JAR files in lib directory for classpath
    jar_files = glob.glob(os.path.join(lib_path, "*.jar"))
    # Include the testcase_dir in classpath so compiled classes can be found
    classpath_parts = [testcase_dir, testcases_path, testcasesupport_path] + jar_files
    classpath = ":".join(classpath_parts)  # Use ";" on Windows, ":" on Unix/Mac
    
    print(f"📚 Classpath: {classpath}")
    
    # Find all Java files to compile
    java_files = []
    
    # Add testcase support files
    for root, _, files in os.walk(testcasesupport_path):
        for file in files:
            if file.endswith(".java"):
                java_files.append(os.path.join(root, file))
    
    # Add main testcase files
    for root, _, files in os.walk(testcases_path):
        for file in files:
            if file.endswith(".java"):
                java_files.append(os.path.join(root, file))
    
    if not java_files:
        print("❌ No Java files found to compile")
        return False
    
    print(f"📝 Found {len(java_files)} Java files to compile")
    
    # Compile in order: support files first, then testcase files
    support_files = [f for f in java_files if "testcasesupport" in f]
    testcase_files = [f for f in java_files if "testcases" in f and "testcasesupport" not in f]
    
    # Compile support files first
    if support_files:
        print("🔨 Compiling support files...")
        success = compile_java_batch(support_files, classpath, testcase_dir)
        if not success:
            return False
    
    # Then compile testcase files
    if testcase_files:
        print("🔨 Compiling testcase files...")
        success = compile_java_batch(testcase_files, classpath, testcase_dir)
        if not success:
            return False
    
    print("✅ Java compilation completed successfully")
    return True

def compile_java_batch(java_files, classpath, testcase_dir):
    """Compile a batch of Java files"""
    try:
        # Build javac command - output to the testcase_dir so .class files are in the right location
        cmd = [
            "javac",
            "-cp", classpath,
            "-d", testcase_dir,  # Output .class files to testcase root directory
            "-encoding", "UTF-8"
        ] + java_files
        
        print(f"⚙️  Running: javac with {len(java_files)} files")
        print(f"🎯 Output directory: {testcase_dir}")
        
        # Run compilation
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=testcase_dir
        )
        
        if result.returncode == 0:
            print("✅ Compilation successful")
            if result.stdout:
                print(f"📄 Output: {result.stdout}")
            return True
        else:
            print(f"❌ Compilation failed (exit code: {result.returncode})")
            if result.stderr:
                print(f"🚨 Error: {result.stderr}")
            if result.stdout:
                print(f"📄 Output: {result.stdout}")
            return False
            
    except FileNotFoundError:
        print("❌ javac not found. Make sure Java Development Kit (JDK) is installed and in PATH")
        return False
    except Exception as e:
        print(f"❌ Compilation error: {e}")
        return False

def main():
    print("🚀 Starting Juliet Test Case Extractor with Compilation")
    
    # Step 1: Read target files from CSV
    target_files = read_csv_targets()
    if not target_files:
        print("❌ No target files found. Exiting.")
        return
    
    print(f"\n📋 Processing {len(target_files)} unique target files...")
    
    # Step 2: Process each target file
    testcase_count = 0
    processed_testcases = set()  # Track processed testcases to avoid duplicates
    compilation_stats = {"success": 0, "failed": 0}
    
    for target_file in target_files:
        print(f"\n{'='*60}")
        print(f"🔍 Processing: {target_file}")
        
        # Get complete testcase structure from manifest
        testcase_files = parse_manifest_for_testcase(target_file)
        
        # Create a unique identifier for this testcase
        testcase_id = tuple(sorted(testcase_files))
        
        # Skip if we've already processed this exact testcase
        if testcase_id in processed_testcases:
            print(f"⏭️  Skipping duplicate testcase")
            continue
            
        processed_testcases.add(testcase_id)
        
        # Create directory for this testcase
        testcase_dir = os.path.join(TARGET_DIR, f"testcase-{testcase_count}")
        new_dir_path = create_directory(testcase_count)
        
        # Get directory structure from the target file
        dir_structure = get_directory_structure_from_file(target_file)
        
        # Create nested directory structure
        current_path = new_dir_path
        for dir_name in dir_structure:
            current_path = create_nested_directory(current_path + "/" + dir_name)
            if current_path is None:
                print(f"❌ Failed to create directory structure")
                break
        
        if current_path is None:
            continue
            
        # Copy all files in this testcase
        files_copied = 0
        for file_name in testcase_files:
            file_path = find_file(JULIET_DS, file_name)
            if file_path:
                copy_file(file_path, current_path)
                files_copied += 1
            else:
                print(f"❌ File not found: {file_name}")
        
        print(f"✅ Testcase {testcase_count}: Copied {files_copied}/{len(testcase_files)} files")
        
        # Compile Java files
        if files_copied > 0:
            if compile_java_files(testcase_dir, testcase_count):
                compilation_stats["success"] += 1
            else:
                compilation_stats["failed"] += 1
        
        testcase_count += 1
    
    print(f"\n🎉 Processing complete!")
    print(f"📊 Created {testcase_count} unique testcase directories")
    print(f"📁 Output location: {TARGET_DIR}")
    print(f"🔨 Compilation results:")
    print(f"   ✅ Successful: {compilation_stats['success']}")
    print(f"   ❌ Failed: {compilation_stats['failed']}")

if __name__ == "__main__":
    main()