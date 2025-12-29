#!/usr/bin/env python3
"""
Utility functions for the Signal Protocol educational demo.
Provides helper functions for printing keys, messages, and formatting output.
"""

import binascii


def print_separator(title: str = "", length: int = 60):
    """
    Print a visual separator with an optional title.

    Args:
        title: Text to display in the center of the separator
        length: Total length of the separator line
    """
    if title:
        # Calculate padding needed for centered title
        padding = length - len(title) - 2  # -2 for the spaces around title
        left_pad = padding // 2
        right_pad = padding - left_pad
        separator = "=" * left_pad + " " + title + " " + "=" * right_pad
    else:
        separator = "=" * length

    print(separator)


def print_hex(data: bytes, label: str = "Data", indent: int = 0):
    """
    Print binary data in hexadecimal format with a descriptive label.

    Args:
        data: Binary data to convert to hex
        label: Descriptive label for the data
        indent: Number of spaces to indent the output
    """
    indent_str = " " * indent
    hex_str = binascii.hexlify(data).decode('ascii')
    print(f"{indent_str}{label}: {hex_str}")


def print_step_header(step_num: int, description: str):
    """
    Print a formatted step header.

    Args:
        step_num: The step number
        description: Brief description of the step
    """
    print_separator(f"STEP {step_num} — {description}")
    print()


def print_explanation(text: str, indent: int = 0):
    """
    Print educational explanation text.

    Args:
        text: The explanation text to print
        indent: Number of spaces to indent
    """
    indent_str = " " * indent
    # Split text into lines and indent each line
    lines = text.split('\n')
    for line in lines:
        print(f"{indent_str}{line}")


def print_message_info(message_num: int, plaintext: str, key_info: str = ""):
    """
    Print information about a message being processed.

    Args:
        message_num: The message number
        plaintext: The original message content
        key_info: Information about the key used
    """
    print(f"Message {message_num}: '{plaintext}'")
    if key_info:
        print(f"  Key: {key_info}")
    print()


def print_attack_info(description: str):
    """
    Print attack simulation information.

    Args:
        description: Description of the attack
    """
    print(f"[ATTACK] {description}")
    print()


def print_result(success: bool, description: str):
    """
    Print the result of an operation.

    Args:
        success: Whether the operation succeeded
        description: Description of the result
    """
    status = "SUCCESS" if success else "FAIL"
    print(f"[{status}] {description}")
    print()
