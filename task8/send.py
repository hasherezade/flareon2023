import socket
import sys
import argparse

def send_to_socket(s, msg):
    s.send(msg)
    result = s.recv(512)
    if result is not None:
        print("[+] Response: " + str(result))
        return True
    return False

def main():
    parser = argparse.ArgumentParser(description="Send to the Crackme")
    parser.add_argument('--port', dest="port", default="8345", help="Port to connect")
    
    wallpaper = None
    with open("wallpaper.bin", "rb") as f:
        wallpaper = f.read()
        print("wallpaper read!");
    
    args = parser.parse_args()
    my_port = int(args.port)
    print('[+] Connecting to port: ' + str(my_port))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', my_port))
        key = bytes.fromhex("6574212c9b4d9334d893bec2477cb86a70983b3c33952d68a8cc5c0226070abf")
        print(key)
        #"12345678901234568901234567890123"
        send_to_socket(s, key)
        nonce = bytes.fromhex("0e02f4a9a8b5beeaba8348d6d2f87c606849df9a5eef49a65c98cf07d4c238a6")
        send_to_socket(s, nonce)
        key = "exec whoami\x0d\0xa"
        msg = key.encode()
        send_to_socket(s, msg)
        
        key = "upload C:\\Users\\tester\\script.ps1 708\r\n"
        msg = key.encode()
        send_to_socket(s, msg)
        
        script = "6d318b7cec938cb399870ce71faf87d3f76024b7b7fb8d11cb4370bd949d364a4bbf5578c248e69e3dff7fe12f90fff6510cde216cc9950a1f5c8b647d65be37bd3d51f71cb99110fbf42dd3821250c0fcda22a022bebc7df1a48c460b9970546fc729b4ef19dec5f32672882e9ff9617366393bc23f5960c03ae0804ae1d6672e84e1f31c2b03faa461d47c803a0cfd93a8400d7e334817aea7e5dd832d3e321db32726bac8f23e7c5978c091c9a6d16c22caba4b44bb8d276da4393c3a146451f1969b58ce526c18f0cddb3fb4afd1197b55b2f15259cf717dd071eb03ee590d28c6eef165b966deb88e1895a8e6fc7e9ece14971379e4e8a0a4fca0b0cbd7435c380007e7fb4c27ce3a6e2a3eb6f0bc6191ef116ace534ca063680ce6fa3734d96844cb4226fd36118fc8d263a75c1e2f4c8f7ff0144bcaa86bef9ead1d17f35045b02d2b02ebee052113304aaeb6e45498b2cfef8b37c16aaa46b1505c4153e656d02d64033bc3df1928ab506168bd0dceced89bb29beaaf77c8b3826a3f56949b35ab9c4eb69fac0e0838bfa90beb5d37fa9fae1af8e2cf2993363e3970f7a622a68229e6b31e9daa2af73710b685906d1ec513d782dc078424b73d0ae6f60f936ca33eb9170aa4b2238ea9cd4f1cfc42392ff6f591fd2ccb933a425ad913699d7094ebbaac118b4acf54e84dd2c38966a44bbf703fcf6116bcddae1c0b5172886f9ce1038cfca1b2bdb44137d3c57660e1eb37837e0c517deda61b3c35ae1ca974d57f3d0ad76389e0ac061069b22303d6dd76ca2073003fe02ed56d5dc06821c9297c052f22f7ba82a68f03a1182ae22fda5e9df4d4a9495f280c5bbe1bf548ed088fb9538454098337ff49667a5ab325b011b9237966e311003a646ad815b103ff73d20145a7e49cf2a4f297529a6da5eeb6cf829edc08c6dfa6d06ee1dede3d714425d0b2ab46fa37cb3a66d5c9a8b7c33dc806e9032b676de088ec0e30d14e"
        s1 = bytes.fromhex(script)
        send_to_socket(s, s1)
        
        # wallpaper
        walp = "a505a116b5e0e6dcb9aa5893268287e491094e1cc392e0cfe30557b09e9208f075d8752bba48c0bc12d1835a5d0d969b3426f00e55ede765de80e5ea6a09dd52ce0f2cb535bff37c80e30db0fc07226dba923bcc4e317844d097f845587f8d73d33b8d7c7a0a8bfbe8f62e55b3f6ee241c04957beb688b5de990b2df18feac1eefc3105483204e89a51ce644d57e60cc90c94526da37fc1369343e089320c46ecb92a6a9719ac01616e69e275465857846dbd45d757ba3835bf68009a2390e8ee13f80a0eb12d707af867673c23db48bd0cb9d53ee94b09ccaa4cb0e097f0cca8d7883a0b532f0b9f6dac3410b13aa166f94d679ea26fb314dd6643917cfc50339cafc151f42c10c3d3a20f284e073a73d16166c7c48e2731f455f147b97bea2d7cbbcd955c47a7adfbb7ebb0cd258cf7383d8e4ad0823576a9a5681de5e2f240e101daedf137ac7ce25016342675266803c78ccd75838aad9c7636aeffcdac6a06aff9bf38686b30845cf6b48cbeb4aa783f885542e2f605eaa1202ddec1e1f23d5da809a7ba4a93a8741c093f28821d14b1ddc38d2194d9554be138999f6fb7c7869642dfb339988a6a0f462dd8c0352aaa62043761c57f927a404c748f9eab368e35c541ed06f1f70150b2cd682a05837ebadec07951c26e60721c56f55e6343f1b54cd1d0502e7ae31c25ec86d63838542e4cb7fe82305fd9d22146c6a39"
        walp1 = bytes.fromhex(script)
        key = "upload C:\\Users\\tester\\wallpaper.PNG 122218\r\n"
        #upload C:\Users\user\AmongRust\wallpaper1.PNG 122218
        msg = key.encode()
        send_to_socket(s, msg)
        send_to_socket(s, wallpaper)
        s.close()
    except socket.error:
        print("Could not connect to the socket. Is the crackme running?")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
