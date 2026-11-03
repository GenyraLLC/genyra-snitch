"""Generate public, synthetic Ethernet/IP traffic; never read a real capture."""
import fcntl,socket,struct,time
from pathlib import Path

def interface():
    return next((p.name for p in Path('/sys/class/net').iterdir() if p.name!='lo'),'lo')

def address(iface):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM)as s:
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s',iface.encode()[:15]))[20:24])

def write_pcap(path,iface=None):
    local=socket.inet_aton(address(iface or interface()))
    def udp(src,dst,sport,dport,payload):
        size=20+8+len(payload)
        return b'\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00'+struct.pack('!BBHHHBBH4s4s',0x45,0,size,0,0,64,17,0,src,dst)+struct.pack('!HHHH',sport,dport,8+len(payload),0)+payload
    targets=[('1.1.1.1','cloudflare-dns.com'),('8.8.8.8','dns.google'),('93.184.216.34','example.com')]
    frames=[]
    for ip,name in targets:
        encoded=b''.join(bytes([len(part)])+part.encode()for part in name.split('.'))+b'\0'
        dns=b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+encoded+b'\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04'+socket.inet_aton(ip)
        frames.append(udp(socket.inet_aton('8.8.8.8'),local,53,42000,dns))
    for i in range(600):
        remote=socket.inet_aton(targets[i%3][0]);frames.append(udp(local,remote,42000+i%20,443,b'fixture traffic '+bytes([65+i%26])*120))
    with open(path,'wb')as f:
        f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,4096,1));now=int(time.time())
        for i,frame in enumerate(frames):f.write(struct.pack('<IIII',now,i*100,len(frame),len(frame))+frame)
    return path
