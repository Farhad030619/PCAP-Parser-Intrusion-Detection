import sys
from unittest.mock import patch, MagicMock
import pytest
from src.cli import main

def test_cli_no_args(capsys):
    with patch.object(sys, 'argv', ['src/cli.py']):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 1
        captured = capsys.readouterr()
        assert "Error: Either a PCAP file or the --live flag must be specified." in captured.err

def test_cli_both_pcap_and_live(capsys):
    with patch.object(sys, 'argv', ['src/cli.py', 'test.pcap', '--live']):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 1
        captured = capsys.readouterr()
        assert "Error: Cannot specify both a PCAP file and --live mode." in captured.err

@patch('src.cli.sniff')
def test_cli_live_default_interface(mock_sniff, capsys):
    with patch.object(sys, 'argv', ['src/cli.py', '--live']):
        main()
    
    mock_sniff.assert_called_once()
    args, kwargs = mock_sniff.call_args
    assert kwargs.get('iface') is None
    assert kwargs.get('store') is False
    assert callable(kwargs.get('prn'))
    
    captured = capsys.readouterr()
    assert "Starting live network sniffing... (Press Ctrl+C to stop)" in captured.out
    assert "default interface" in captured.out
    assert "Analysis completed" in captured.out

@patch('src.cli.sniff')
def test_cli_live_specified_interface(mock_sniff, capsys):
    with patch.object(sys, 'argv', ['src/cli.py', '--live', '-i', 'eth0']):
        main()
        
    mock_sniff.assert_called_once()
    args, kwargs = mock_sniff.call_args
    assert kwargs.get('iface') == 'eth0'
    assert kwargs.get('store') is False
    
    captured = capsys.readouterr()
    assert "Starting live network sniffing... (Press Ctrl+C to stop)" in captured.out
    assert "eth0" in captured.out

@patch('src.cli.sniff', side_effect=KeyboardInterrupt)
def test_cli_live_keyboard_interrupt(mock_sniff, capsys):
    with patch.object(sys, 'argv', ['src/cli.py', '--live']):
        main()
        
    captured = capsys.readouterr()
    assert "Stopping live sniffing..." in captured.out
    assert "Analysis completed" in captured.out
