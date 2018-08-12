#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import datetime
import dpkt as pc
import time
import dpkt
import socket
import pyshark
import tempfile
import re
import subprocess

class colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def Banner():

	print ("__________.__                      __  .__       .__                                   ")
	print ("\______   \  |__ _____    ____   _/  |_|__| ____ |  |__   ______   ____ _____  ______  ")
	print (" |     ___/  |  \\__  \  /    \  \   __\  |/ ___\|  |  \  \____ \_/ ___\\__  \ \____ \ ")
	print (" |    |   |   Y  \/ __ \|   |  \  |  | |  \  \___|   Y  \ |  |_> >  \___ / __ \|  |_> >")
	print (" |____|   |___|  (____  /___|  /  |__| |__|\___  >___|  / |   __/ \___  >____  /   __/ ")
	print ("               \/     \/     \/                \/     \/  |__|        \/     \/|__|    ' \n")


	print colors.GREEN + (" "*43+"[+Công cụ phân tích gói tin pcap+]") + colors.END
	print colors.RED   + (" "*47+"[Phiên bản v1.0(BETA)]") + colors.END
	print colors.BLUE  + (" "*47+"[tkien202]") + colors.END

	print colors.BOLD + ("[!]CONTACT[!]\n| Email: tkien2021990@gmail.com |\n| Github: github/tkien202     |\n| Facebook: @tkien202          |\n") + colors.END

Banner()


def configure():

	try:
		with open('/usr/share/wireshark/init.lua', 'r') as f:
			replace = []
			for line in f.readlines():
				replace.append(line.replace('disable_lua = false', 'disable_lua = true'))
		with open('/usr/share/wireshark/init.lua', 'w') as f:
			for line in replace:
				f.write(line)
	except:
		None

def check():
	configure()
	reads = (os.popen("tshark -h")).read()
	print ("[+] Kiểm tra công cụ tshark...")

	if 'WARNING' in reads:
		print colors.BOLD + ("[+] Tìm thấy tshark! Bắt đầu!\n") + colors.END
		configure()
		pass

	else:
		print colors.RED + ("[-] Không tìm thấy Tshark!") + colors.END
		print colors.RED + ("Cài đặt Tshark..") + colors.END
		print (os.system("apt-get -y install tshark"))
		print colors.RED + ("[+]Đang cấu hình vui lòng đợi..") + colors.END



check()

print colors.GREEN + "+++++++++++++++++++++++++++++++++++++++" + colors.END
print colors.BOLD + ("1 -Phân tích tệp tin pcap") + colors.END
print colors.RED + ("** Tùy chọn này được sử dụng để phân tích các tệp 'pcap'. **\n") +colors.END
print colors.BOLD + ("2 -PHÂN TÍCH THỜI GIAN THỰC (ĐANG HOÀN THIỆN)") + colors.END
print colors.RED + ("** Tùy chọn này được sử dụng để phân tích gói tin theo thời gian thực. **") +colors.END
print colors.GREEN + "+++++++++++++++++++++++++++++++++++++++\n" + colors.END


def packet():

		pcap = raw_input("Location Pcap File > ")
		if pcap == pcap:
			control = (os.popen("file " '%s' %pcap)).read()
			if 'capture file' in control:
				print ("[+] Đã nhận dạng tệp tin\n")
				pass
			else:
				print colors.RED + ("Đây không phải tệp tin định dạng pcap\n Thoát..") + colors.END
				sys.exit()
		while True:

			print "\n"
			print colors.BLUE + (" " * 25 + "|-CÁC HOẠT ĐỘNG-|\n") + colors.END
			print(" 1-Top 10 trang hay ghé thăm" + " " * 13 + "2-Trích xuất Emails\n")
			print(" 3-Tất cả các đường dẫn yêu cầu" + " " * 10 + "4-Danh sách trình duyệt\n")
			print(" 5-Tra cứu theo chuỗi" + " " * 20 + "6-Chi tiết các kết nối\n")
			print(" 7-Các cổng đã được sử dụng" + " " * 14 + "8-Danh sách tất cả IP\n")
			print(" 9-Lọc gói tin thủ công" + " " * 18 + "10- Phân tích Smtp\n")
			print("              11-Phát hiện tấn công Web")


			pack = raw_input(colors.BLUE + "\nHoạt động số > " + colors.END)
			print "\n"

			if pack == "1":
				top10 = os.popen("tshark -T fields -e http.host -r '%s' | sort | uniq -c | sort -nr" % pcap).read()
				print colors.RED + ("Top 10 trang hay ghé thăm\n\nSố lần yêu cầu | HOST") + colors.END
				print (top10)

			elif pack == "2":
				print colors.RED + ("Trích xuất Emails\n") + colors.END
				print colors.RED + ("Cảnh báo! Có khả năng xảy ra lỗi(%80)\n") + colors.END
				email = os.popen("ngrep -q -I '%s'" %pcap).read()
				reg = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b", email)

				st = set()
				uniq = [allmail for allmail in reg if allmail not in st and not st.add(allmail)]

				for onering in uniq:
					print (onering)


			elif pack == "3":

				contol = os.popen("file '%s'" % pcap).read()

				if "tcpdump" in contol:
					f = file(pcap, "rb")
					pcap2 = pc.pcap.Reader(f)
					pass
				else:
					print ("[Lỗi!]Không TcpDump được tệp tin\n")
					print ("Đang chuyển đổi định dạng 'tcpdump'. Vui lòng đợi..\n")
					print ("--------------------------------")
					print ("Ví dụ : tenteptin.pcap")
					name = raw_input("Mời đặt tên mới : ")
					print ("--------------------------------\n")
					tmp = tempfile.NamedTemporaryFile(delete=False)
					time.sleep(2)
					converter = os.popen("mergecap '%s' -w %s'%s' -F pcap" % (pcap,tmp.name, name))
					print ("[+]Khởi tạo %s%s \n\nTiến trình đang hoạt động vui lòng đợi...\n" % (tmp.name,name))
					time.sleep(3)
					fin = (tmp.name+name)
					f = file(fin, 'rb')
					pcap2 = pc.pcap.Reader(f)

				def ips(inet):

					try:
						return socket.inet_ntop(socket.AF_INET, inet)
					except ValueError:
						return socket.inet_ntop(socket.AF_INET6, inet)

				for ts, nul in pcap2:
					adr = pc.ethernet.Ethernet(nul)

					ip = adr.data
					tcp = ip.data
					timestamp = time.time()

					try:

						if tcp.dport == 80 and len(tcp.data) > 0:
							try:
								http = pc.http.Request(tcp.data)
							except (pc.dpkt.UnpackError, AttributeError):
								continue


							if isinstance(ip.data, pc.tcp.TCP):  # İnstance Örnekleme Değişken Atama.

								print ("------------------------------------------------------------------------")
								print "Thời gian           : ", str(datetime.datetime.utcfromtimestamp(timestamp))
								print "HTPP Địa chỉ    : ", http.headers['host']
								print "HTTP URI       : ", http.uri
								print 'Nguồn         :  %s\nĐích    :  %s   NOTE :-> (Length=%d - TTL Value=%d)' % (
									ips(ip.src), ips(ip.dst), ip.len, ip.ttl)
								print "Trình duyệt     : ", http.headers['user-agent']
								print "Đã sửa đổi kể từ : ", http.headers['if-modified-since']

					except:
						pass

				print "\n"
				print colors.RED+ "Đầu ra thay thế"

				request = os.popen("tshark -T fields -e http.host -e http.request.uri -Y 'http.request.method == \"GET\"' -r '%s' | sort | uniq" %pcap).read()

				print ("----------------------------------------------------------")
				print colors.RED + ("    Host             |               Yêu cầu URI\n") + colors.END
				print ("----------------------------------------------------------")
				print (request)
				print ("----------------------------------------------------------")


			elif pack == "4":
				userA = os.popen(
					"tshark -Y 'http contains \"User-Agent:\"' -T fields -e http.user_agent -r '%s' | sort | uniq -c | sort -nr" % pcap).read()
				print colors.RED + ("Bao nhiêu | Danh sách Trình duyệt\n") + colors.END
				print (userA)


			elif pack == "5":

				stingr = raw_input(colors.YELLOW + "Search String : " + colors.END)

				print colors.RED + ("Kết quả\n") + colors.END
				response = subprocess.call("ngrep -q -I '%s' | grep -i '%s' | sort | uniq -c" % (pcap, stingr),
											shell=True)

			elif pack == "6":

				print ("\na- Thống kê IO")
				print ("b- Cây giao thức")
				print ("c- Chi tiết các phiên (TCP,IP,UDP)")
				print ("d- Tất cả chi tiết các phiên\n")

				itachi = raw_input("\nWhich ? > ")

				if itachi == "a":
					io = subprocess.call("tshark -r '%s' -qz io,stat,10,tcp,udp,icmp,ip,smtp,smb,arp,browser" %pcap , shell=True)

				elif itachi == "b":
					prototree = subprocess.call("tshark -r '%s' -qz io,phs" %pcap, shell=True)

				elif itachi == "c": # Protocol if : else control Error..

					print colors.RED + ( "Phiên TCP\n") + colors.END

					tcpt = subprocess.call("tshark -r '%s' -qz conv,tcp" % (pcap), shell=True)

					print colors.RED + ("Phiên IP\n") + colors.END

					ipt = subprocess.call("tshark -r '%s' -qz conv,ip" % (pcap), shell=True)

					print colors.RED + ("Phiên UDP\n") + colors.END

					udpt = subprocess.call("tshark -r '%s' -qz conv,udp" % (pcap), shell=True)

				elif itachi == "d":

					print colors.RED + ("Tất cả chi tiết các phiên\n") + colors.END
					conver = pyshark.FileCapture('%s' %pcap)

					def conversat(converpack):
						try:

							proto     = converpack.transport_layer
							src_addr  = converpack.ip.src
							src_port  = converpack[converpack.transport_layer].srcport
							dst_addr  = converpack.ip.dst
							dst_port  = converpack[converpack.transport_layer].dstport
							print ("Giao thức: " '%s' "  -  ""Nguồn: " '%s'" - Cổng: "'%s' " ----> " "Đích: " '%s'" - Cổng: "'%s' %(proto,src_addr,src_port,dst_addr,dst_port))

						except AttributeError:
							pass
					conver.apply_on_packets(conversat, timeout=50)


			elif pack == "7":

				print colors.RED + "Bao nhiêu | Cổng sử dụng" + colors.END

				port = subprocess.call("tcpdump -nn -r '%s' -p 'tcp or udp' | awk -F' ' '{print $5}' | awk -F'.' '{print $5}' | sed 's/:/ /g'  | sort | uniq -c | sort -n" %pcap, shell=True)

			elif pack == "8":

				print colors.RED + "Danh sách tất cả các địa chỉ IP\n" + colors.END

				ipls = os.popen("tcpdump -nn -r '%s' -p 'tcp or udp'" %pcap).read()
				ipreg = re.findall(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", ipls)

				st2 = set()
				uniq2 = [allip for allip in ipreg if allip not in st2 and not st2.add(allip)]

				for sauron in uniq2:
					print  (colors.YELLOW+"[+]"+colors.END+colors.BLUE +sauron+colors.END )

				print "\n"

				print colors.RED + "[+Thêm]Yêu cầu danh sách IP\n" + colors.END

				reqipl = os.popen("tcpdump -nn -r '%s' -p 'tcp or udp' | awk -F' ' '{print $3}' | awk -F'.' '{print $1\".\"$2\".\"$3\".\"$4}' | sort | uniq | sort -n" %pcap).read()


				print (colors.BLUE+reqipl+colors.END)


			elif pack == "9":

				print colors.YELLOW + "Lọc gói tin thủ công" + colors.END
				print colors.BLUE + "Tham chiếu bộ lọc:\nhttps://www.wireshark.org/docs/dfref/\nhttps://wiki.wireshark.org/DisplayFilters\n" +colors.END

				filt = raw_input("Filter > ")

				try:
					filtr = pyshark.FileCapture(pcap, display_filter='%s' %filt)

					for tr in filtr:
						print (tr)
				except:
					return

			elif pack == "10":

				print colors.RED + "Thông tin SMTP\n" + colors.END

				list_key = ['Date:', 'To:', 'Subject:', 'From:', 'X-Mailer', 'Pass','User']
				app_list = []
				smtp = file(pcap, "rb")

				for s in smtp:
					for word in list_key:
						if s.startswith(word):
							app_list.append(s)

				for list_ in app_list:
					print colors.BLUE + (list_) + colors.END

			elif pack == "11":

				sql = ['UNION', 'SELECT', 'CONCAT', 'FROM', 'union', 'select', '@@version', 'substring', 'information',
					   'table_name', 'from', 'convert', 'concat']
				xss = ['%3Cscript%3E', 'ALeRt', 'ScriPt', '<script>', '</script>', 'alert(\'xss\')', 'XSS', 'xss',
					   'alert(', '\';alert', 'onerror', 'document.cookie', 'onmouseover', '<img>', '<SCRIPT>',
					   'SCscriptIPT', 'scSCRIPTipt', 'onfocus=alert', 'alALERTert', 'String.fromCharCode']
				lfi = ['../../', '..//..//', '../', '/etc/passwd', '/etc/', '/proc/self/environ', '%00',
					   'php://filter/convert.base64-encode/resource=', 'cat /etc/passwd', 'system()', 'exec()',
					   'whoami']  # & Code Exec


				openpack = open(pcap)
				pcap11 = dpkt.pcap.Reader(openpack)
				app = []

				print (colors.YELLOW+"\nPhát hiện tấn công Web\n\nInclude Modules:\n[+XSS]\n[+LFİ]\n[+SQLİ]\n"+colors.END)

				for ts, buf in pcap11:
					eth = dpkt.ethernet.Ethernet(buf)
					ip = eth.data
					tcp = ip.data

					try:

						if tcp.dport == 80 and len(tcp.data) > 0:
							http = dpkt.http.Request(tcp.data)
							asd = str(http.uri)
							tata = app.append(asd)

							for url in app:
								pass

							for vuln in sql:
								if vuln in url:
									try:
										print colors.RED + "SQLİ Attack URL: " + colors.END, url

									except:
										AttributeError

							for vuln2 in xss:
								if vuln2 in url:
									try:
										print colors.BLUE + "XSS Attack URL: " + colors.END, url
									except:
										AttributeError

							for vuln3 in lfi:
								if vuln3 in url:
									try:
										print colors.YELLOW + "LFİ Attack URL: " + colors.END, url
									except:
										AttributeError

					except:
						AttributeError


try:
	if __name__ == '__main__':
		select = raw_input("Lựa chọn > ")

		if select == "1":
			packet()
		if select == "2":
			print colors.RED+("Hẹn gặp lại")+colors.END
except:
	KeyboardInterrupt
	print ("Thoát ứng dụng..")
