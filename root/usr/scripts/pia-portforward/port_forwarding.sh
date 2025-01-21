#!/usr/bin/env bash
# Copyright (C) 2020 Private Internet Access, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This function allows you to check if the required tools have been installed.
check_tool() {
  cmd=$1
  if ! command -v "$cmd" >/dev/null; then
    echo "$cmd could not be found"
    echo "Please install $cmd"
    exit 1
  fi
}

# Now we call the function to make sure we can use curl and jq.
check_tool curl
check_tool jq

# if no gateway found, use our public internet access which is likely correct
if [[ -z $PF_GATEWAY ]]; then
	PF_GATEWAY=$(curl -s ifconfig.me)
	if [[ -z $PF_GATEWAY ]]; then
		echo "Failed to find gateway IP using curl -s ifconfig.me - try passing a \$PF_GATEWAY ip"
		exit 1
	fi
	echo "Auto detected gateway PF_GATEWAY=$PF_GATEWAY"
fi

# If no hostname, we could skip TLS checks with --insecure.  However, this may skip other CA cert verificaations, and there's 
# no way from the curl CLI to simply ignore the name but still check the rest of the cert (there is via the C LIB via CURLOPT_SSL_VERIFYHOST). 
# So instead we retrieve the server name by looking at the subject name of the "rejected" cert and then will use it. I'm not sure if this even helps,
# but can't seem worse than simply ignoring it.  Of course the best way would be to pass the PF_HOSTNAME, and this simply makes all the code match
if [[ -z $PF_HOSTNAME ]]; then
	PF_HOSTNAME=$(curl -Gs --cacert "ca.rsa.4096.crt" --connect-timeout 5 --verbose "https://$PF_GATEWAY:19999" 2>&1 | sed -nE 's/.*CN=([a-zA-Z0-9]*)[;\s]?.*/\1/p')
	if [[ -z $PF_HOSTNAME ]]; then
		echo "Failed to find gateway certificate subject hostname from gateway server at https://$PF_GATEWAY:19999 - try passing \$PF_HOSTNAME instead"
		exit 1
	fi
	echo "Auto detected host PF_HOSTNAME=$PF_HOSTNAME from certificate at $PF_GATEWAY"
fi

if [[ -z $PIA_TOKEN ]]; then
	if [[ ! -z $PIA_USER && ! -z $PIA_PASS ]]; then

		echo -n "Checking login credentials..."

		generateTokenResponse=$(curl -s --location --request POST \
		  'https://www.privateinternetaccess.com/api/client/v2/token' \
		  --form "username=$PIA_USER" \
		  --form "password=$PIA_PASS" )

		if [ "$(echo "$generateTokenResponse" | jq -r '.token')" == "" ]; then
		  echo -e "${red}Could not authenticate with the login credentials provided!${nc}"
		  exit 1
		fi

		PIA_TOKEN=$(echo "$generateTokenResponse" | jq -r '.token')
	fi
fi


# Check if the mandatory environment variables are set.
if [[ -z $PIA_TOKEN ]]; then
  echo "This script requires env vars:"
  echo "PIA_TOKEN   - the token you use to connect to the vpn services, or pass PIA_USER and PIA_PASS to request one"
  echo "PF_GATEWAY  - the IP of your gateway, or if not passed will retrieve using \"curl ifconfig.me\""
  echo 
  echo "PF_HOSTNAME - name of the host used for SSL/TLS certificate verification, or if not passed will skip verification"
  echo "PIA_USER    - PIA user account, eg pXXXXXXX to use to retrieve an auth token"
  echo "PIA_PASS    - PIA password for PIA_USER to use to retrieve an auth token"
  echo
  echo "Derived from: https://github.com/pia-foss/manual-connections"
  exit 1
fi

# Check if terminal allows output, if yes, define colors for output
if [[ -t 1 ]]; then
#  ncolors=$(tput colors)
#  if [[ -n $ncolors && $ncolors -ge 8 ]]; then
#    red=$(tput setaf 1) # ANSI red
#    green=$(tput setaf 2) # ANSI green
#    nc=$(tput sgr0) # No Color
#  else
    red=''
    green=''
    nc='' # No Color
#  fi
fi


# The port forwarding system has required two variables:
# PAYLOAD: contains the token, the port and the expiration date
# SIGNATURE: certifies the payload originates from the PIA network.

# Basically PAYLOAD+SIGNATURE=PORT. You can use the same PORT on all servers.
# The system has been designed to be completely decentralized, so that your
# privacy is protected even if you want to host services on your systems.

# You can get your PAYLOAD+SIGNATURE with a simple curl request to any VPN
# gateway, no matter what protocol you are using. Considering WireGuard has
# already been automated in this repo, here is a command to help you get
# your gateway if you have an active OpenVPN connection:
# $ ip route | head -1 | grep tun | awk '{ print $3 }'
# This section will get updated as soon as we created the OpenVPN script.

# Get the payload and the signature from the PF API. This will grant you
# access to a random port, which you can activate on any server you connect to.
# If you already have a signature, and you would like to re-use that port,
# save the payload_and_signature received from your previous request
# in the env var PAYLOAD_AND_SIGNATURE, and that will be used instead.
if [[ -z $PAYLOAD_AND_SIGNATURE ]]; then
  echo
  echo -n "Getting new signature... "
  payload_and_signature="$(curl -s -m 5 \
    --connect-to "$PF_HOSTNAME::$PF_GATEWAY:" \
    --cacert "ca.rsa.4096.crt" \
    -G --data-urlencode "token=${PIA_TOKEN}" \
    "https://${PF_HOSTNAME}:19999/getSignature")"
else
  payload_and_signature=$PAYLOAD_AND_SIGNATURE
  echo -n "Checking the payload_and_signature from the env var... "
fi
export payload_and_signature

# Check if the payload and the signature are OK.
# If they are not OK, just stop the script.
if [[ $(echo "$payload_and_signature" | jq -r '.status') != "OK" ]]; then
  echo -e "${red}The payload_and_signature variable does not contain an OK status.${nc}"
  exit 1
fi

# We need to get the signature out of the previous response.
# The signature will allow the us to bind the port on the server.
signature=$(echo "$payload_and_signature" | jq -r '.signature')

# The payload has a base64 format. We need to extract it from the
# previous response and also get the following information out:
# - port: This is the port you got access to
# - expires_at: this is the date+time when the port expires
payload=$(echo "$payload_and_signature" | jq -r '.payload')
port=$(echo "$payload" | base64 -d | jq -r '.port')

# The port normally expires after 2 months. If you consider
# 2 months is not enough for your setup, please open a ticket.
expires_at=$(echo "$payload" | base64 -d | jq -r '.expires_at')

echo -ne "
Signature ${green}$signature${nc}
Payload   ${green}$payload${nc}

--> The port is ${green}$port${nc} and it will expire on ${red}$expires_at${nc}. <--
"

# Make sure above succeeded 
if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 20000 && port <= 65535 )); then
    false
else
    echo "Bad port received... exiting"
    exit 1
fi

echo -e Forwarded port'\t'"${green}$port${nc}"
echo -e Refreshed on'\t'"${green}$(date)${nc}"
echo -e Expires on'\t'"${red}$(date --date="$expires_at")${nc}"
echo -e "\n${green}This script will need to remain active to use port forwarding, and will refresh every 15 minutes.${nc}\n"

# Grab some directories and info from config file
CONF_FILE=/config/qBittorrent/qBittorrent.conf
CERT=$(sed -nE 's/.*WebUI\\HTTPS\\CertificatePath=(.*)/\1/p' $CONF_FILE)
PRIVKEY=$(sed -nE 's/.*WebUI\\HTTPS\\KeyPath=(.*)/\1/p' $CONF_FILE)
SSL_EN=$(sed -nE 's/.*WebUI\\HTTPS\\Enabled=(true|false).*/\1/p' $CONF_FILE)
HTTP=$([ "$SSL_EN" = "true" ] && echo "https" || echo "http") 
TORRENTING_PORT=$(sed -nE 's/.*Session\\Port=([0-9]+).*/\1/p' $CONF_FILE)
WEBUI_LISTEN_PORT=$(sed -nE 's/.*WebUI\\Port=([0-9]+).*/\1/p' $CONF_FILE)
SERVE_PORT=8443
TEMPDIR=$(mktemp -d -t port_forward_www.XXXXXXXXXX)

echo "Serving forwarded port value at $HTTP://0.0.0.0:8443/port.txt"

# Trap to cleanup the web server if we exit for any reason, since it may otherwise run forever and lock up the listening port
trap 'rm -rf $TEMPDIR && kill $(jobs -p) 2>/dev/null' EXIT                                                                    
python3 simple_https_server.py --dir $TEMPDIR --port 8443 --host 0.0.0.0 --key $PRIVKEY --cert $CERT &
SERVER_PID=$!
sleep 1		# wait long enough to see if above fails
if ! ps -p $SERVER_PID > /dev/null; then
	echo "Server terminated early... ending"
	exit 1
fi
    
# Now we have all required data to create a request to bind the port.
# We will repeat this request every 15 minutes, in order to keep the port
# alive. The servers have no mechanism to track your activity, so they
# will just delete the port forwarding if you don't send keepalives.
while true; do
  bind_port_response="$(curl -Gs -m 5 \
    --connect-to "$PF_HOSTNAME::$PF_GATEWAY:" \
    --cacert "ca.rsa.4096.crt" \
    --data-urlencode "payload=${payload}" \
    --data-urlencode "signature=${signature}" \
    "https://${PF_HOSTNAME}:19999/bindPort")"

    # If port did not bind, just exit the script.
    # This script will exit in 2 months, since the port will expire.
    #export bind_port_response
    if [[ $(echo "$bind_port_response" | jq -r '.status') != "OK" ]]; then
        echo -e "${red}The API did not return OK when trying to bind port... Exiting.${nc}"
        exit 1
    else 
        echo "Refreshed port binding on $port"
    fi
    
    # This really only needs to be done once, but we'll do it after we bind the first time (and all others)    
    echo $port > $TEMPDIR/port.txt
    
    # Send API command to change port.  Note that this requires the setting for no authorization from localhost, otherwise must have password to auth and not done here
    HTTP_RESP=$(curl -k -s "$HTTP://localhost:$WEBUI_LISTEN_PORT/api/v2/app/setPreferences" -d 'json={"listen_port": "'"$port"'"}' -o /dev/null -w "%{http_code}")
    if [ "$HTTP_RESP" != "200" ]; then
	echo "qbittorrent API returned status \"$HTTP_RESP\" when updating listen port - check that \"Bypass authentication for clients on localhost\" is checked or update this code"
	exit 1
    fi

    # Force tracker re-announce... hmm... the API docs say this should be a query/URL parameter, but works this way...
    curl -k -s "$HTTP://localhost:$WEBUI_LISTEN_PORT/api/v2/torrents/reannounce" -d "hashes=all" 
    # ignore response here
    
    # Update the config file - note that this seems to be written on the above API call too so this should be an effective NOP
    # sed -i 's/Session\\Port=.*/Session\\Port='$port'/g' /config/qBittorrent/qBittorrent.conf

    # sleep 5 minutes
    sleep 300    

done


