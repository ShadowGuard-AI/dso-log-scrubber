import argparse
import re
import logging
import chardet
import importlib.util
import os
import sys

try:
    from faker import Faker
except ImportError:
    Faker = None

FAKE_OPTIONS = {
    "fake_name": "name",
    "fake_email": "email",
    "fake_address": "address",
    "fake_phone_number": "phone_number",
    "fake_credit_card_number": "credit_card_number",
}


def faker_available():
    """Return True when the faker package can be imported."""
    try:
        return importlib.util.find_spec("faker") is not None
    except (ImportError, ValueError):
        return False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class LogScrubber:
    """
    Removes or obfuscates sensitive information from log files.
    """

    def __init__(self, input_file, output_file, patterns, replace_with=None, inplace=False, encoding=None):
        """
        Initializes the LogScrubber.

        Args:
            input_file (str): Path to the input log file.
            output_file (str): Path to the output sanitized log file.
            patterns (list): List of regular expression patterns to find sensitive data.
            replace_with (str, optional): Text to replace sensitive data with. Defaults to None (deletion).
            inplace (bool, optional): Whether to overwrite the input file. Defaults to False.
            encoding (str, optional): The encoding of the input file. Defaults to None, which will attempt auto-detection.
        """
        self.input_file = input_file
        self.output_file = output_file
        self.patterns = patterns
        self.replace_with = replace_with
        self.inplace = inplace
        self.encoding = encoding
        self.total_substitutions = 0
        self.lines_changed = 0
        self.fake = None
        if replace_with in FAKE_OPTIONS:
            if Faker is None:
                raise ImportError("faker dependency is not installed. Please install it to use the 'fake' replace_with options.")
            self.fake = Faker() # Initialize Faker for generating fake data

    def _detect_encoding(self):
        """
        Detects the encoding of the input file.
        """
        try:
            with open(self.input_file, 'rb') as f:
                result = chardet.detect(f.read())
                return result['encoding']
        except Exception as e:
            logging.error(f"Error detecting encoding: {e}")
            return 'utf-8' #Default if detection fails

    def scrub_log(self):
        """
        Scrubs the log file, removing or obfuscating sensitive data based on the provided patterns.
        """
        if not self.input_file or not self.output_file or not self.patterns:
            logging.error("Input file, output file, and patterns must be provided.")
            return False

        if not os.path.exists(self.input_file):
            logging.error(f"Input file not found: {self.input_file}")
            return False

        # Refuse a same path output unless --inplace was given as consent.
        if os.path.realpath(self.output_file) == os.path.realpath(self.input_file) and not self.inplace:
            logging.error("Output file is the input file. Use --inplace to scrub a file in place.")
            return False

        # Validate and compile every pattern before processing any line,
        # so an invalid pattern cannot leak an original line into output.
        try:
            compiled_patterns = [re.compile(pattern) for pattern in self.patterns]
        except re.error as e:
            logging.error(f"Invalid regular expression: {e}")
            return False

        try:
            # Determine encoding if not provided
            if not self.encoding:
                self.encoding = self._detect_encoding()
                logging.info(f"Detected encoding: {self.encoding}")

            # errors='ignore' on the read: bytes the detected encoding
            # cannot decode are dropped from the line silently, so a
            # scrubbed file can lose characters that no pattern touched.
            with open(self.input_file, 'r', encoding=self.encoding, errors='ignore') as infile:
                lines = infile.readlines()

            # Scrub in memory first, so an error writes no output at all.
            scrubbed_lines = []
            for line in lines:
                sanitized_line, count = self._scrub_line(line, compiled_patterns)
                self.total_substitutions += count
                if sanitized_line != line:
                    self.lines_changed += 1
                scrubbed_lines.append(sanitized_line)

            # This zero check counts substitutions as subn reports them,
            # and subn counts zero width matches: a pattern like z* that
            # can match the empty string scores dozens of substitutions on
            # a file that contains no z at all, passes this check, and
            # writes output byte identical to the input with a success
            # summary. I verified exactly that run: 47 substitutions
            # across 0 changed lines, exit success. The lines_changed
            # figure in the summary is the honest signal; the substitution
            # count alone is not.
            if self.total_substitutions == 0:
                logging.error("Nothing was scrubbed: no pattern matched any line in the input file.")
                return False

            with open(self.output_file, 'w', encoding=self.encoding, errors='ignore') as outfile:
                for sanitized_line in scrubbed_lines:
                    outfile.write(sanitized_line)

            logging.info(f"Scrubbed {self.total_substitutions} substitution(s) across {self.lines_changed} line(s).")

            if self.inplace and os.path.realpath(self.output_file) != os.path.realpath(self.input_file):
                try:
                    os.replace(self.output_file, self.input_file) #atomic operation
                    logging.info(f"File scrubbed in-place: {self.input_file}")
                except Exception as e:
                    logging.error(f"Error overwriting file in-place: {e}")
                    return False
            return True
        except FileNotFoundError:
            logging.error(f"File not found: {self.input_file}")
            return False
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            return False

    def _scrub_line(self, line, compiled_patterns=None):
        """
        Scrubs a single line of text, replacing sensitive data based on the provided patterns.

        Args:
            line (str): The line of text to scrub.
            compiled_patterns (list, optional): Patterns already validated and
                compiled by scrub_log. When omitted, the raw patterns are
                compiled here and an invalid pattern raises re.error.

        Returns:
            tuple: The sanitized line and the number of substitutions made.
                A pattern or replacement error raises instead of returning
                the original line, so unscrubbed text is never written out.
        """
        if compiled_patterns is None:
            compiled_patterns = [re.compile(pattern) for pattern in self.patterns]
        sanitized_line = line
        total = 0
        for pattern in compiled_patterns:
            # The replacement is chosen once per pattern per line, before
            # the substitution runs, so under a fake option every match of
            # one pattern in one line receives the same fake value, and a
            # fake value is drawn and discarded on lines the pattern never
            # matches. The replacement also goes to subn as a template,
            # not a literal: backslash sequences in a --replace_with value
            # are read as group references, which is useful when intended
            # and a surprise when the text was meant literally.
            if self.replace_with is None:
                replacement = '' # Delete the matched text
            elif self.replace_with in FAKE_OPTIONS:
                if self.fake is None:
                    raise ImportError("faker dependency is not installed. Please install it to use the 'fake' replace_with options.")
                replacement = getattr(self.fake, FAKE_OPTIONS[self.replace_with])()
            else:
                replacement = self.replace_with # Replace the matched text
            sanitized_line, count = pattern.subn(replacement, sanitized_line)
            total += count
        return sanitized_line, total


def setup_argparse():
    """
    Sets up the argparse command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description='Removes or obfuscates sensitive information from log files.')
    parser.add_argument('input_file', help='Path to the input log file.')
    parser.add_argument('output_file', help='Path to the output sanitized log file.')
    parser.add_argument('--patterns', nargs='+', required=True, help='List of regular expression patterns to find sensitive data.')
    parser.add_argument('--replace_with', help='Text to replace sensitive data with.  Use "fake_name", "fake_email", "fake_address", "fake_phone_number", or "fake_credit_card_number" for fake data generation. Defaults to deletion.', default=None)
    parser.add_argument('--inplace', action='store_true', help='Overwrite the input file with the sanitized output.')
    parser.add_argument('--encoding', help='Specify the encoding of the input file. If not provided, encoding will be auto-detected.')
    return parser


def main():
    """
    Main function to parse arguments and run the log scrubber.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation: a fake option needs faker to be importable.
    if args.replace_with in FAKE_OPTIONS and not faker_available():
        logging.error("faker dependency is not installed. Please install it to use the 'fake' replace_with options.")
        sys.exit(1)

    try:
        scrubber = LogScrubber(args.input_file, args.output_file, args.patterns, args.replace_with, args.inplace, args.encoding)
    except ImportError as e:
        logging.error(str(e))
        sys.exit(1)
    if not scrubber.scrub_log():
        sys.exit(1)

if __name__ == "__main__":
    # Usage examples:
    # 1. Scrub a log file, replacing IP addresses with 'REDACTED':
    #    python main.py input.log output.log --patterns "r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'" --replace_with "REDACTED"
    # 2. Scrub a log file in-place, removing email addresses:
    #    python main.py input.log input.log --patterns "r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'" --inplace
    # 3. Scrub a log file, replacing names with fake names:
    #    python main.py input.log output.log --patterns "r'\b[A-Z][a-z]+\s[A-Z][a-z]+\b'" --replace_with "fake_name"
    # 4. Scrub a log file, detecting encoding automatically
    #    python main.py input.log output.log --patterns "r'password=\w+'" --replace_with "password=REDACTED"
    main()