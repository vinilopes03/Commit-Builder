import os
import re
from typing import Dict, List, Tuple, Optional
from openai import OpenAI


class VulnerabilityTestGenerator:
    """Generates JUnit tests to verify security vulnerabilities."""
    
    # CWE test templates mapping
    CWE_TEMPLATES = {
        "CWE15": {
            "name": "External Control of System Setting",
            "test_method": "setConfiguration"
        },
        "CWE78": {
            "name": "OS Command Injection", 
            "test_method": "executeCommand"
        },
        "CWE80": {
            "name": "Reflected XSS",
            "test_method": "processInput"
        },
        "CWE81": {
            "name": "Script in Error Message",
            "test_method": "generateErrorMessage"
        },
        "CWE83": {
            "name": "Script in Attributes",
            "test_method": "processAttribute"
        },
        "CWE89": {
            "name": "SQL Injection",
            "test_method": "buildQuery"
        },
        "CWE113": {
            "name": "HTTP Response Splitting",
            "test_method": "bad"
        },
        "CWE129": {
            "name": "Improper Array Index Validation",
            "test_method": "accessArray"
        },
        "CWE134": {
            "name": "Uncontrolled Format String",
            "test_method": "formatString"
        },
        "CWE606": {
            "name": "Unchecked Loop Condition",
            "test_method": "processLoop"
        }
    }
    
    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
    
    def extract_cwe_from_filename(self, filename: str) -> Optional[str]:
        """Extract CWE identifier from filename."""
        match = re.search(r'CWE(\d+)', filename)
        return f"CWE{match.group(1)}" if match else None
    
    def extract_package_and_class(self, java_code: str) -> Tuple[str, str]:
        """Extract package and class name from Java source."""
        package_match = re.search(r'package\s+([a-zA-Z0-9_.]+);', java_code)
        package = package_match.group(1) if package_match else "testcases"
        
        class_match = re.search(r'public\s+class\s+(\w+)', java_code)
        class_name = class_match.group(1) if class_match else "MainClass"
        
        return package, class_name
    
    def gather_support_classes(self, support_dir: str) -> str:
        """Collect all support Java files from directory."""
        if not support_dir or not os.path.isdir(support_dir):
            return ""
        
        support_content = ""
        for root, _, files in os.walk(support_dir):
            for filename in files:
                if filename.endswith(".java"):
                    filepath = os.path.join(root, filename)
                    with open(filepath, "r") as f:
                        code = f.read()
                    relative_path = os.path.relpath(filepath, support_dir)
                    support_content += f"\n- {relative_path}\n```java\n{code}\n```\n"
        
        return support_content
    
    def get_test_template(self, cwe_id: str) -> str:
        """Get the appropriate test template for the CWE."""
        templates = {
            "CWE15": """package {package};

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class {test_class} {{

    @Test
    void testCWE15_ExternalControlOfSystemSetting() throws Exception {{
        String maliciousInput = "malicious.config.value";
        try {{
            {main_class} instance = new {main_class}();
            instance.setConfiguration(maliciousInput);
            String result = System.getProperty("some.config.key");
            assertTrue(result != null && result.equals(maliciousInput), 
                "Vulnerability present: Configuration set with untrusted input");
        }} catch (Throwable t) {{
            fail("Vulnerability fixed or absent: Configuration setting was blocked or sanitized");
        }}
    }}
}}""",

            "CWE78": """package {package};

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class {test_class} {{

    @Test
    void testCWE78_OSCommandInjection() throws Exception {{
        String maliciousInput = "; malicious_command";
        try {{
            {main_class} instance = new {main_class}();
            String result = instance.executeCommand(maliciousInput);
            assertTrue(result != null && result.contains("malicious"), 
                "Vulnerability present: Command executed with malicious input");
        }} catch (Throwable t) {{
            fail("Vulnerability fixed or absent: Command execution was blocked or sanitized");
        }}
    }}
}}""",

            "CWE80": """package {package};

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class {test_class} {{

    @Test
    void testCWE80_XSS() throws Exception {{
        String maliciousInput = "<script>alert('xss')</script>";
        {main_class} instance = new {main_class}();
        String output = instance.processInput(maliciousInput);
        boolean reflected = output.contains("<script>");
        boolean escaped = output.contains("&lt;script&gt;");
        assertTrue(reflected && !escaped, 
            "Vulnerability present: Script tag reflected without sanitization");
    }}
}}""",

            "CWE81": """package {package};

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class {test_class} {{

    @Test
    void testCWE81_ScriptInErrorMessage() throws Exception {{
        String maliciousInput = "<script>alert('xss')</script>";
        {main_class} instance = new {main_class}();
        String errorMessage = instance.generateErrorMessage(maliciousInput);
        assertTrue(errorMessage.contains("<script>"), 
            "Vulnerability present: Script in error message not sanitized");
    }}
}}""",

            "CWE83": """package {package};

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class {test_class} {{

    @Test
    void testCWE83_ScriptInAttributes() throws Exception {{
        String maliciousInput = "onerror=alert('xss')";
        {main_class} instance = new {main_class}();
        String output = instance.processAttribute(maliciousInput);
        assertTrue(output.contains("onerror=alert"), 
            "Vulnerability present: Script in attribute not sanitized");
    }}
}}""",

            "CWE89": """package {package};

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class {test_class} {{

    @Test
    void testCWE89_SQLInjection() throws Exception {{
        String maliciousInput = "' OR '1'='1";
        {main_class} instance = new {main_class}();
        try {{
            String query = instance.buildQuery(maliciousInput);
            boolean injectionRisk = query.toLowerCase().contains("' or '1'='1") || 
                                  query.contains(maliciousInput);
            assertTrue(injectionRisk, 
                "Vulnerability present: SQL input used unsafely in query");
        }} catch (Throwable t) {{
            fail("Vulnerability fixed or query construction failed safely");
        }}
    }}
}}""",

            "CWE113": """package {package};

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.mockito.ArgumentCaptor;
import javax.servlet.http.*;

public class {test_class} {{

    @Test
    void testCWE113_HTTPResponseSplitting() throws Exception {{
        String maliciousInput = "en-US%0d%0aSet-Cookie:evil=1";
        {main_class} instance = new {main_class}();
        HttpServletResponse response = mock(HttpServletResponse.class);

        try {{
            instance.bad(null, response);
        }} catch (Throwable t) {{
            fail("Vulnerability fixed or not triggered: Exception occurred");
        }}

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(response).addCookie(cookieCaptor.capture());
        Cookie added = cookieCaptor.getValue();

        boolean isVulnerable = added.getValue().contains("\\r") || 
                             added.getValue().contains("\\n") || 
                             added.getValue().contains("%0d%0a");
        assertTrue(isVulnerable, 
            "Vulnerability fixed or input sanitized: CRLF not propagated to cookie value");
    }}
}}""",

            "CWE129": """package {package};

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class {test_class} {{

    @Test
    void testCWE129_ImproperArrayIndexValidation() throws Exception {{
        int invalidIndex = -1;
        try {{
            {main_class} instance = new {main_class}();
            instance.accessArray(invalidIndex);
            fail("Vulnerability fixed: No exception thrown for invalid array index");
        }} catch (ArrayIndexOutOfBoundsException e) {{
            assertTrue(true, "Vulnerability present: Invalid index causes exception");
        }} catch (Throwable t) {{
            fail("Vulnerability fixed: Array index is validated");
        }}
    }}
}}""",

            "CWE134": """package {package};

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class {test_class} {{

    @Test
    void testCWE134_UncontrolledFormatString() throws Exception {{
        String maliciousInput = "%n%s";
        {main_class} instance = new {main_class}();
        try {{
            String output = instance.formatString(maliciousInput);
            assertTrue(output != null, 
                "Vulnerability present: Format string processed unsafely");
        }} catch (Throwable t) {{
            fail("Vulnerability fixed: Format string is sanitized or handled safely");
        }}
    }}
}}""",

            "CWE606": """package {package};

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class {test_class} {{

    @Test
    void testCWE606_UncheckedLoopCondition() throws Exception {{
        int maliciousInput = -1;
        try {{
            {main_class} instance = new {main_class}();
            instance.processLoop(maliciousInput);
            fail("Vulnerability fixed: Loop ran with unchecked input");
        }} catch (Throwable t) {{
            assertTrue(true, "Vulnerability present: Unchecked loop condition causes issue");
        }}
    }}
}}"""
        }
        
        # Return the specific template if it exists
        if cwe_id in templates:
            return templates[cwe_id]
        
        # Generic fallback template
        cwe_info = self.CWE_TEMPLATES.get(cwe_id, {})
        method_name = cwe_info.get("test_method", "processInput")
        vulnerability_name = cwe_info.get("name", "security vulnerability")
        
        return f"""package {{package}};

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class {{test_class}} {{
    
    @Test
    void test{cwe_id}_{vulnerability_name.replace(' ', '')}() throws Exception {{
        // Test for {cwe_id}: {vulnerability_name}
        {{main_class}} instance = new {{main_class}}();
        
        // TODO: Implement specific test for {method_name} method
        fail("Test not implemented for {cwe_id}");
    }}
}}"""
    
    def build_prompt(self, cwe_id: str, package: str, main_class: str, 
                    test_class: str, main_code: str, support_classes: str) -> str:
        """Build the GPT prompt for test generation."""
        template = self.get_test_template(cwe_id).format(
            package=package,
            main_class=main_class,
            test_class=test_class
        )
        
        return f"""You are an expert Java security engineer. Generate a JUnit 5 test to verify if the code is vulnerable to {cwe_id}.

REQUIREMENTS:
- Generate ONE compilable JUnit test class
- The test should PASS if the vulnerability exists
- The test should FAIL if the code is secure
- Include all necessary imports
- Handle any exceptions appropriately
- Use Mockito for mocking when needed (especially for servlets)
- Target the actual public methods in the main class

CWE: {cwe_id}
Package: {package}
Main class: {main_class}
Test class: {test_class}

Reference template:
```java
{template}
```

Main class to test:
```java
{main_code}
```

Supporting classes:
{support_classes}

Output ONLY the complete Java test code."""
    
    def generate_test(self, main_java_file: str, support_dir: str, 
                     output_dir: str) -> Optional[str]:
        """Generate a JUnit test for the given Java file."""
        # Read main file
        with open(main_java_file, "r") as f:
            main_code = f.read()
        
        # Extract metadata
        package, main_class = self.extract_package_and_class(main_code)
        test_class = f"{main_class}Test"
        
        # Determine CWE from filename
        cwe_id = self.extract_cwe_from_filename(os.path.basename(main_java_file))
        if not cwe_id or cwe_id not in self.CWE_TEMPLATES:
            print(f"Warning: Unknown CWE, defaulting to CWE113")
            cwe_id = "CWE113"
        
        # Gather support classes
        support_classes = self.gather_support_classes(support_dir)
        
        # Build and send prompt
        prompt = self.build_prompt(cwe_id, package, main_class, test_class, 
                                 main_code, support_classes)
        
        print(f"Generating {cwe_id} test for {main_class}...")
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert Java security engineer."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            response_text = response.choices[0].message.content
        except Exception as e:
            print(f"Error calling GPT: {e}")
            return None
        
        # Extract code from response
        match = re.search(r"```java(.*?)```", response_text, re.DOTALL)
        test_code = match.group(1).strip() if match else response_text.strip()
        
        # Save test file
        os.makedirs(output_dir, exist_ok=True)
        test_filepath = os.path.join(output_dir, f"{test_class}.java")
        
        with open(test_filepath, "w") as f:
            f.write(test_code)
        
        print(f"✅ Test saved to: {test_filepath}")
        return test_filepath


def generate_junit_vulnerability_test(main_java_file: str, support_java_dir: str,
                                    output_test_dir: str, api_key: str,
                                    model: str = "gpt-4o-mini") -> Optional[str]:
    """Legacy function wrapper for backward compatibility."""
    generator = VulnerabilityTestGenerator(api_key, model)
    return generator.generate_test(main_java_file, support_java_dir, output_test_dir)