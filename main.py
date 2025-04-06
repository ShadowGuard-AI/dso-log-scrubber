import argparse
import re
import logging
import chardet
from faker import Faker
import os
import sys

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
            return

        if not os.path.exists(self.input_file):
            logging.error(f"Input file not found: {self.input_file}")
            return

        try:
            # Determine encoding if not provided
            if not self.encoding:
                self.encoding = self._detect_encoding()
                logging.info(f"Detected encoding: {self.encoding}")

            with open(self.input_file, 'r', encoding=self.encoding, errors='ignore') as infile:
                lines = infile.readlines()

            with open(self.output_file, 'w', encoding=self.encoding, errors='ignore') as outfile:
                for line in lines:
                    sanitized_line = self._scrub_line(line)
                    outfile.write(sanitized_line)

            if self.inplace:
                try:
                    os.replace(self.output_file, self.input_file) #atomic operation
                    logging.info(f"File scrubbed in-place: {self.input_file}")
                except Exception as e:
                    logging.error(f"Error overwriting file in-place: {e}")
        except FileNotFoundError:
            logging.error(f"File not found: {self.input_file}")
        except Exception as e:
            logging.error(f"An error occurred: {e}")

    def _scrub_line(self, line):
        """
        Scrubs a single line of text, replacing sensitive data based on the provided patterns.

        Args:
            line (str): The line of text to scrub.

        Returns:
            str: The sanitized line of text.
        """
        sanitized_line = line
        for pattern in self.patterns:
            try:
                if self.replace_with is None:
                    sanitized_line = re.sub(pattern, '', sanitized_line) # Delete the matched text
                elif self.replace_with == "fake_name":
                     sanitized_line = re.sub(pattern, self.fake.name(), sanitized_line)
                elif self.replace_with == "fake_email":
                    sanitized_line = re.sub(pattern, self.fake.email(), sanitized_line)
                elif self.replace_with == "fake_address":
                    sanitized_line = re.sub(pattern, self.fake.address(), sanitized_line)
                elif self.replace_with == "fake_phone_number":
                    sanitized_line = re.sub(pattern, self.fake.phone_number(), sanitized_line)
                elif self.replace_with == "fake_credit_card_number":
                    sanitized_line = re.sub(pattern, self.fake.credit_card_number(), sanitized_line)
                else:
                    sanitized_line = re.sub(pattern, self.replace_with, sanitized_line) # Replace the matched text

            except re.error as e:
                logging.error(f"Invalid regular expression: {pattern} - {e}")
                return line  # Return the original line if there's an error
        return sanitized_line


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

    # Input validation
    if args.replace_with in ["fake_name", "fake_email", "fake_address", "fake_phone_number", "fake_credit_card_number"] and not all(["faker" in dep for dep in sys.modules]):
        logging.error("faker dependency is not installed. Please install it to use the 'fake' replace_with options.")
        return


    scrubber = LogScrubber(args.input_file, args.output_file, args.patterns, args.replace_with, args.inplace, args.encoding)
    scrubber.scrub_log()

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