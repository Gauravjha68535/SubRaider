#!/bin/bash
#
# SubRaider - Pillage The Web For Subdomains
# https://github.com/gauravjha68535/SubRaider
# By: Gaurav Jha
# Version: 1.0.0

VERSION="1.0.0"
CONFIG_FILE="$HOME/.config/subraider/config"

# Pirate Colors - Yarr! ☠️
bold="\e[1m"
red="\e[31m"
green="\e[32m"
yellow="\e[33m"
blue="\e[34m"
purple="\e[35m"
cyan="\e[36m"
orange="\e[38;5;208m"
gold="\e[38;5;220m"
end="\e[0m"

# Default variables
treasure=False
treasure_map=False
crew=False
mutiny=False
quiet_mode=False
cleanup_plunder=True
chest=False
cannon=False
sailors=40
parley=False
deep_raid=False
depth=2
booty_format="txt"
cutlass="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
compass="/usr/share/wordlists/resolvers.txt"
plunder_stats=False
board=False
flag=False
raid_dir="subraider_plunder"
blitzkrieg=False
blackspot=False
broadside=100
config_loaded=False

# Crew registry (modules)
declare -a crew=(
    "wayback_machine" "crows_nest" "dnd" "naval_intel" "rum_harbor" 
    "treasure_trails" "ship_logs" "harbor_master" "fast_sloop" "deep_hunter" 
    "scallywag" "cannon_brigade" "parrot_whisperer" "dead_mans_chest" "jolly_roger" 
    "kraken" "leviathan" "sea_shanty" "siren_song" "typhoon" 
    "maelstrom" "riptide" "blackbeard" "captain_kidd" "anne_bonny"
)

# Load buried treasure (config)
load_map() {
    [ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"
    config_loaded=True
}

# Bury new treasure (save config)
bury_treasure() {
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" << EOF
# SubRaider - Buried Treasure Map ☠️
VT_API_KEY="$VT_API_KEY"
ST_API_KEY="$ST_API_KEY"
CENSYS_ID="$CENSYS_ID"
CENSYS_SECRET="$CENSYS_SECRET"
CHAOS_KEY="$CHAOS_KEY"
SHODAN_KEY="$SHODAN_KEY"
GITHUB_TOKEN="$GITHUB_TOKEN"
EOF
    echo -e "${gold}[✓] Treasure buried at $CONFIG_FILE${end}"
}

# Show the pirate code (help)
parley() {
    cat << EOF
${orange}${bold}☠️  SubRaider v$VERSION - Pillage The Seven Digital Seas ☠️${end}

${gold}${bold}Usage:${end} ./subraider.sh [options]

${cyan}${bold}Target Vessels:${end}
    -t, --target DOMAIN       Target ship to plunder
    -T, --targets FILE        Map of multiple targets
    -R, --raid [N]            Deep raid mode (depth N, default: 2)

${cyan}${bold}Crew Control:${end}
    -c, --crew LIST           Which pirates to bring (comma-separated)
    -m, --mutiny LIST         Pirates to walk the plank
    -A, --all-crew            Summon the entire fleet
    --fast-sloop              Quick raid (skip heavy cannons)

${cyan}${bold}Plunder Options:${end}
    -o, --chest FILE          Where to bury the treasure
    -f, --format TYPE         Treasure format: txt, json, csv, html (default: txt)
    -q, --quiet               Silent as a ghost ship
    --keep-plunder            Keep all stolen goods (temp files)
    --plunder-stats           Count your doubloons

${cyan}${bold}Boarding Actions:${end}
    -p, --board               Board live vessels (HTTP probe)
    -s, --sailors NUM         Number of sailors (threads, default: 40)
    --compass FILE            Navigational resolvers
    --board-verify            Verify with cannons (HTTP probes)
    --flag                    Raise your flag (screenshots)
    --timeout SEC             Cannon reload time (default: 5)

${cyan}${bold}Heavy Cannons:${end}
    -C, --cutlass FILE        Custom sword (wordlist)
    --rum                     Release the rum (permutations)
    --depth NUM               How deep to dig (default: 2)
    --broadside NUM           Cannon firing rate (default: 100)

${cyan}${bold}Advanced Tactics:${end}
    -P, --blackspot PROXY     Use the blackspot (proxy)
    --blitzkrieg              Blitzkrieg - full broadside
    --map FILE                Custom treasure map (config)
    --bury-treasure           Initialize configuration
    --update-map              Update SubRaider
    --crew-check              Check if pirates are ready

${gold}${bold}Examples:${end}
    ./subraider.sh -t example.com -A -p --plunder-stats
    ./subraider.sh -T targets.txt --fast-sloop -o booty.txt
    ./subraider.sh -t example.com -c crows_nest,rum_harbor -p --flag
    ./subraider.sh -t example.com --raid 3 --rum -C cutlass.txt

${orange}${bold}Available Pirates:${end}
    ${crew[*]}
EOF
    exit 1
}

# Pirate spinner ☠️
parrot_spinner() {
    local pid=$1
    local msg="$2"
    local spin='🏴‍☠️ ⚓ 🏴‍☠️ ⚓'
    local i=0
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r[${spin:$i:2}] %s" "$msg"
        sleep 0.2
    done
    printf "\r[✅] %s\n" "$msg"
}

# Check the crew's readiness
crew_check() {
    local missing=()
    local optional=()
    
    echo -e "${cyan}[*] Mustering the crew...${end}"
    
    for tool in findomain subfinder amass assetfinder httprobe jq parallel curl; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done
    
    for tool in shuffledns dnsgen altdns gotator chromium gowitness; do
        if ! command -v "$tool" &>/dev/null; then
            optional+=("$tool")
        fi
    done
    
    [ ${#missing[@]} -gt 0 ] && {
        echo -e "${red}[!] Missing crew members: ${missing[*]}${end}"
        echo "Recruit them with: ./install.sh"
        exit 1
    }
    
    [ ${#optional[@]} -gt 0 ] && [ "$quiet_mode" == False ] && {
        echo -e "${yellow}[!] Optional pirates missing: ${optional[*]}${end}"
    }
    
    echo -e "${green}[✓] All hands on deck!${end}"
}

# Module: Wayback Machine - The Ancient Archive
wayback_machine() {
    local cmd="curl -sk 'http://web.archive.org/cdx/search/cdx?url=*.$treasure&output=txt&fl=original&collapse=urlkey&page=' | awk -F/ '{gsub(/:.*/, \"\", \$3); print \$3}' | sort -u"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-wayback-$treasure" || {
        eval "$cmd" > "tmp-wayback-$treasure" &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}📜 Wayback Machine${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Ancient Archive${end}: $(wc -l < tmp-wayback-$treasure 2>/dev/null)"
    }
}

# Module: crt.sh - The Crow's Nest
crows_nest() {
    local cmd="curl -sk 'https://crt.sh/?q=%.$treasure&output=json' | tr ',' '\n' | awk -F'\"' '/name_value/ {gsub(/\*\./, \"\", \$4); gsub(/\\n/,\"\n\",\$4); print \$4}' | sort -u"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-crow-$treasure" || {
        eval "$cmd" > "tmp-crow-$treasure" &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}🔭 Crow's Nest${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Crow's Nest${end}: $(wc -l < tmp-crow-$treasure 2>/dev/null)"
    }
}

# Module: DNS BufferOver - Drowned in Data
dnd() {
    local cmd="curl -s 'https://dns.bufferover.run/dns?q=.$treasure' | grep $treasure | awk -F, '{gsub(\"\\\"\", \"\", \$2); print \$2}' | sort -u"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-dnd-$treasure" || {
        eval "$cmd" > "tmp-dnd-$treasure" &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}🌊 Drowned DNS${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Drowned DNS${end}: $(wc -l < tmp-dnd-$treasure 2>/dev/null)"
    }
}

# Module: ThreatCrowd - Naval Intelligence
naval_intel() {
    local cmd="curl -sk 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$treasure' | jq -r '.subdomains[]' 2>/dev/null"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-navy-$treasure" || {
        eval "$cmd" > "tmp-navy-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}⚓ Naval Intel${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Naval Intel${end}: $(wc -l < tmp-navy-$treasure 2>/dev/null)"
    }
}

# Module: VirusTotal - Rum Harbor (where pirates gather)
rum_harbor() {
    [ -z "$VT_API_KEY" ] && return
    local cmd="curl -sk 'https://www.virustotal.com/api/v3/domains/$treasure/subdomains' -H 'x-apikey: $VT_API_KEY' | jq -r '.data[].id' 2>/dev/null"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-rum-$treasure" || {
        eval "$cmd" > "tmp-rum-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}🏴‍☠️ Rum Harbor${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Rum Harbor${end}: $(wc -l < tmp-rum-$treasure 2>/dev/null)"
    }
}

# Module: SecurityTrails - Treasure Trails
treasure_trails() {
    [ -z "$ST_API_KEY" ] && return
    local cmd="curl -sk 'https://api.securitytrails.com/v1/domain/$treasure/subdomains' -H 'APIKEY: $ST_API_KEY' | jq -r '.subdomains[]' 2>/dev/null | awk -v domain='$treasure' '{print \$1\".\"domain}'"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-trails-$treasure" || {
        eval "$cmd" > "tmp-trails-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}🗺️ Treasure Trails${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Treasure Trails${end}: $(wc -l < tmp-trails-$treasure 2>/dev/null)"
    }
}

# Module: CertSpotter - Ship's Logs
ship_logs() {
    local cmd="curl -sk 'https://api.certspotter.com/v1/issuances?domain=$treasure&include_subdomains=true&expand=dns_names' | jq -r '.[].dns_names[]' 2>/dev/null | grep '\\.$treasure' | sed 's/^\\*\\.//' | sort -u"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-logs-$treasure" || {
        eval "$cmd" > "tmp-logs-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}📓 Ship's Logs${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Ship's Logs${end}: $(wc -l < tmp-logs-$treasure 2>/dev/null)"
    }
}

# Module: HackerTarget - Harbor Master
harbor_master() {
    local cmd="curl -sk 'https://api.hackertarget.com/hostsearch/?q=$treasure' | cut -d, -f1"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-harbor-$treasure" || {
        eval "$cmd" > "tmp-harbor-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}⚓ Harbor Master${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Harbor Master${end}: $(wc -l < tmp-harbor-$treasure 2>/dev/null)"
    }
}

# Module: RapidDNS - Fast Sloop
fast_sloop() {
    local cmd="curl -sk 'https://rapiddns.io/subdomain/$treasure?full=1' | grep -oP '([a-zA-Z0-9._-]+\\.$treasure)' | sort -u"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-sloop-$treasure" || {
        eval "$cmd" > "tmp-sloop-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}⛵ Fast Sloop${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Fast Sloop${end}: $(wc -l < tmp-sloop-$treasure 2>/dev/null)"
    }
}

# Module: Anubis - Deep Hunter
deep_hunter() {
    local cmd="curl -sk 'https://jldc.me/anubis/subdomains/$treasure' | jq -r '.[]' 2>/dev/null"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-hunter-$treasure" || {
        eval "$cmd" > "tmp-hunter-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}🐊 Deep Hunter${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Deep Hunter${end}: $(wc -l < tmp-hunter-$treasure 2>/dev/null)"
    }
}

# Module: Chaos - Scallywag (ProjectDiscovery Chaos)
scallywag() {
    [ -z "$CHAOS_KEY" ] && return
    local cmd="chaos -d $treasure -key $CHAOS_KEY -silent 2>/dev/null"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-scallywag-$treasure" || {
        eval "$cmd" > "tmp-scallywag-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}🏴 Scallywag${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Scallywag${end}: $(wc -l < tmp-scallywag-$treasure 2>/dev/null)"
    }
}

# Module: URLScan - Cannon Brigade
cannon_brigade() {
    local cmd="curl -sk 'https://urlscan.io/api/v1/search/?q=domain:$treasure' | jq -r '.results[].page.domain' 2>/dev/null | grep '\\.$treasure' | sort -u"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-cannon-$treasure" || {
        eval "$cmd" > "tmp-cannon-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}🔫 Cannon Brigade${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Cannon Brigade${end}: $(wc -l < tmp-cannon-$treasure 2>/dev/null)"
    }
}

# Module: CommonCrawl - Parrot Whisperer
parrot_whisperer() {
    local cmd="curl -sk 'http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.$treasure&output=json' | jq -r '.url' 2>/dev/null | awk -F/ '{gsub(/:.*/, \"\", \$3); print \$3}' | grep '\\.$treasure' | sort -u"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-parrot-$treasure" || {
        eval "$cmd" > "tmp-parrot-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}🦜 Parrot Whisperer${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Parrot Whisperer${end}: $(wc -l < tmp-parrot-$treasure 2>/dev/null)"
    }
}

# Module: Findomain - Dead Man's Chest
dead_mans_chest() {
    local cmd="findomain -t $treasure -q 2>/dev/null"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-chest-$treasure" || {
        eval "$cmd" > "tmp-chest-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}💀 Dead Man's Chest${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Dead Man's Chest${end}: $(wc -l < tmp-chest-$treasure 2>/dev/null)"
    }
}

# Module: SubFinder - Jolly Roger
jolly_roger() {
    local cmd="subfinder -all -silent -d $treasure 2>/dev/null"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-roger-$treasure" || {
        eval "$cmd" > "tmp-roger-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}🏴 Jolly Roger${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Jolly Roger${end}: $(wc -l < tmp-roger-$treasure 2>/dev/null)"
    }
}

# Module: Amass - The Kraken
kraken() {
    [ "$fast_sloop" == True ] && return
    local cmd="amass enum -passive -norecursive -noalts -d $treasure 2>/dev/null"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-kraken-$treasure" || {
        eval "$cmd" > "tmp-kraken-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}🐙 The Kraken${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] The Kraken${end}: $(wc -l < tmp-kraken-$treasure 2>/dev/null)"
    }
}

# Module: AssetFinder - Leviathan
leviathan() {
    local cmd="assetfinder --subs-only $treasure"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-leviathan-$treasure" || {
        eval "$cmd" > "tmp-leviathan-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}🐋 Leviathan${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Leviathan${end}: $(wc -l < tmp-leviathan-$treasure 2>/dev/null)"
    }
}

# Module: ShuffleDNS - Sea Shanty
sea_shanty() {
    command -v shuffledns &>/dev/null || return
    [ ! -f "$cutlass" ] && return
    [ ! -f "$compass" ] && return
    local cmd="shuffledns -d $treasure -w $cutlass -r $compass -mode bruteforce -silent 2>/dev/null"
    [ "$quiet_mode" == True ] && eval "$cmd" >> "tmp-shanty-$treasure" || {
        eval "$cmd" > "tmp-shanty-$treasure" 2>/dev/null &
        local pid=$!
        [ "$parley" == False ] && parrot_spinner $pid "${bold}🎵 Sea Shanty${end}"
        wait $pid
        [ "$parley" == False ] && echo -e "${bold}[*] Sea Shanty${end}: $(wc -l < tmp-shanty-$treasure 2>/dev/null)"
    }
}

# Module: Permutations - Siren Song
siren_song() {
    [ ! -f "$cutlass" ] && return
    local tmp_permute="tmp-siren-base-$treasure"
    cat tmp-* 2>/dev/null | sort -u > "$tmp_permute"
    
    if command -v dnsgen &>/dev/null; then
        cat "$tmp_permute" | dnsgen - -w "$cutlass" 2>/dev/null | grep "\\.$treasure$" > "tmp-dnsgen-$treasure"
    fi
    
    if command -v altdns &>/dev/null; then
        altdns -i "$tmp_permute" -w "$cutlass" -o "tmp-altdns-$treasure" &>/dev/null
    fi
    
    if command -v gotator &>/dev/null; then
        gotator -sub "$tmp_permute" -perm "$cutlass" -depth 1 -numbers 10 -md 2>/dev/null | grep "\\.$treasure$" > "tmp-gotator-$treasure"
    fi
    
    if command -v puredns &>/dev/null && [ -f "$compass" ]; then
        cat tmp-* 2>/dev/null | sort -u | puredns resolve -r "$compass" 2>/dev/null > "tmp-resolved-siren-$treasure"
    fi
}

# Board the vessel (resolve)
board_vessel() {
    local plunder="$1"
    local ship="$2"
    
    mkdir -p "$raid_dir/live"
    
    if command -v httprobe &>/dev/null; then
        cat "$plunder" | httprobe -c "$sailors" -t "$timeout" > "$raid_dir/live/http-$ship.txt"
        echo -e "${green}[✓] Live vessels:${end} $(wc -l < $raid_dir/live/http-$ship.txt)"
    fi
    
    if [ "$board" == True ] && command -v httpx &>/dev/null; then
        cat "$plunder" | httpx -silent -status-code -title -tech-detect -o "$raid_dir/live/httpx-$ship.txt"
    fi
    
    if [ "$flag" == True ]; then
        mkdir -p "$raid_dir/flags"
        if command -v gowitness &>/dev/null; then
            cat "$raid_dir/live/http-$ship.txt" | gowitness file -f - -P "$raid_dir/flags" --no-http &>/dev/null
        elif command -v aquatone &>/dev/null; then
            cat "$raid_dir/live/http-$ship.txt" | aquatone -out "$raid_dir/flags" -silent &>/dev/null
        fi
        echo -e "${green}[✓] Flags raised:${end} $raid_dir/flags"
    fi
}

# Count the booty (stats)
count_booty() {
    local chest="$1"
    [ ! -f "$chest" ] && return
    
    echo -e "\n${gold}${bold}[+] Plunder Statistics${end}"
    echo -e "${cyan}Total doubloons:${end} $(wc -l < "$chest")"
    
    echo -e "\n${yellow}Pirate flags (TLDs):${end}"
    awk -F. '{print $NF}' "$chest" | sort | uniq -c | sort -rn | head -5
    
    echo -e "\n${yellow}How deep we dug:${end}"
    awk -F. '{print NF-1}' "$chest" | sort -n | uniq -c
    
    echo -e "\n${yellow}Booty size:${end}"
    awk '{print length}' "$chest" | sort -n | uniq -c | head -5
}

# Format the treasure
shape_booty() {
    local plunder="$1"
    local style="$2"
    local chest="$3"
    
    case "$style" in
        json)
            jq -R -s 'split("\n") | map(select(length > 0))' < "$plunder" > "${chest%.*}.json"
            echo -e "${green}[✓] JSON treasure:${end} ${chest%.*}.json"
            ;;
        csv)
            sed 's/$/,/' < "$plunder" > "${chest%.*}.csv"
            echo -e "${green}[✓] CSV treasure:${end} ${chest%.*}.csv"
            ;;
        html)
            {
                echo "<!DOCTYPE html><html><head><title>SubRaider Plunder</title>"
                echo "<style>body{font-family:'Courier New';margin:40px;background:#000;color:#ffd700}h1{color:#ff4500}.sub{color:#00ced1}</style>"
                echo "</head><body><h1>🏴‍☠️ SubRaider Results for $treasure 🏴‍☠️</h1><pre>"
                cat "$plunder"
                echo "</pre></body></html>"
            } > "${chest%.*}.html"
            echo -e "${green}[✓] HTML treasure map:${end} ${chest%.*}.html"
            ;;
        txt)
            cp "$plunder" "$chest"
            echo -e "${green}[✓] TXT booty:${end} $chest"
            ;;
    esac
}

# Deep raid (recursive)
deep_raid() {
    local target="$1"
    local current_depth="${2:-1}"
    local max_depth="${3:-2}"
    
    [ $current_depth -gt $max_depth ] && return
    
    echo -e "\n${cyan}${bold}[*] Deep raid (depth: $current_depth/$max_depth): $target${end}"
    
    treasure="$target"
    launch_raid
    
    local result_file="$chest"
    [ -f "$result_file" ] || result_file="$treasure-$(date +%Y%m%d).txt"
    
    if [ -f "$result_file" ]; then
        while read sub; do
            local new_target=$(echo "$sub" | rev | cut -d. -f1-3 | rev)
            if [ "$new_target" != "$target" ] && [[ "$new_target" == *."$treasure" ]]; then
                deep_raid "$new_target" $((current_depth + 1)) "$max_depth"
            fi
        done < "$result_file"
    fi
}

# Launch the raid (main enumeration)
launch_raid() {
    local pirates=("${@}")
    
    if [ "$parley" == True ]; then
        export -f ${crew[@]} wayback_machine crows_nest dnd naval_intel rum_harbor treasure_trails ship_logs harbor_master fast_sloop deep_hunter scallywag cannon_brigade parrot_whisperer dead_mans_chest jolly_roger kraken leviathan sea_shanty siren_song parrot_spinner
        export treasure quiet_mode bold end
        parallel ::: "${pirates[@]}"
    else
        for pirate in "${pirates[@]}"; do
            $pirate
        done
    fi
}

# Main raid function
main_raid() {
    # Create raid directory
    mkdir -p "$raid_dir"
    
    # Load treasure map
    [ "$config_loaded" == False ] && load_map
    
    # Check crew
    [ "$crew_check" == True ] && crew_check
    
    # Process targets
    if [ "$treasure" != False ]; then
        if [ "$deep_raid" == True ]; then
            deep_raid "$treasure" 1 "$depth"
        else
            launch_raid "${selected_crew[@]}"
            
            # Combine all plunder
            local timestamp=$(date +%Y%m%d-%H%M%S)
            local default_chest="$raid_dir/$treasure-$timestamp.txt"
            local final_chest="${chest:-$default_chest}"
            
            cat tmp-* 2>/dev/null | sort -u > "$final_chest"
            echo -e "\n${gold}[✓] Total doubloons:${end} $(wc -l < $final_chest)"
            
            # Shape the booty
            shape_booty "$final_chest" "$booty_format" "$final_chest"
            
            # Board vessels
            [ "$cannon" == True ] && board_vessel "$final_chest" "$treasure"
            
            # Count plunder
            [ "$plunder_stats" == True ] && count_booty "$final_chest"
            
            # Clean up
            [ "$cleanup_plunder" == True ] && rm -f tmp-* 2>/dev/null
        fi
    elif [ "$treasure_map" != False ] && [ -f "$treasure_map" ]; then
        local total=$(wc -l < "$treasure_map")
        local count=1
        while read d; do
            echo -e "\n${orange}${bold}[$count/$total] Raiding: $d${end}"
            treasure="$d"
            main_raid
            ((count++))
        done < "$treasure_map"
    else
        parley
    fi
}

# Parse the parley (arguments)
while [ $# -gt 0 ]; do
    case $1 in
        -t|--target) treasure="$2"; shift ;;
        -T|--targets) treasure_map="$2"; shift ;;
        -R|--raid) deep_raid=True; [ -n "$2" ] && [ "${2#*-}" = "$2" ] && depth="$2" && shift ;;
        -c|--crew) crew="$2"; IFS=',' read -ra selected_crew <<< "$2"; shift ;;
        -m|--mutiny) mutiny="$2"; IFS=',' read -ra mutiny_crew <<< "$2"; shift ;;
        -A|--all-crew) selected_crew=("${crew[@]}") ;;
        --fast-sloop) fast_sloop=True; selected_crew=("wayback_machine" "crows_nest" "dnd" "fast_sloop" "dead_mans_chest" "jolly_roger" "leviathan") ;;
        -o|--chest) chest="$2"; shift ;;
        -f|--format) booty_format="$2"; shift ;;
        -q|--quiet) quiet_mode=True ;;
        --keep-plunder) cleanup_plunder=False ;;
        -p|--board) cannon=True ;;
        -s|--sailors) sailors="$2"; shift ;;
        --compass) compass="$2"; shift ;;
        --board-verify) board=True ;;
        --flag) flag=True ;;
        --timeout) timeout="$2"; shift ;;
        -C|--cutlass) cutlass="$2"; shift ;;
        --rum) rum=True ;;
        --depth) depth="$2"; shift ;;
        --broadside) broadside="$2"; shift ;;
        -P|--blackspot) blackspot="$2"; export HTTP_PROXY="$blackspot"; export HTTPS_PROXY="$blackspot"; shift ;;
        --blitzkrieg) blitzkrieg=True; sailors=200; depth=5; rum=True ;;
        --map) CONFIG_FILE="$2"; shift ;;
        --bury-treasure) load_map; bury_treasure; exit 0 ;;
        --update-map) git pull origin main; exit 0 ;;
        --crew-check) crew_check=True ;;
        --plunder-stats) plunder_stats=True ;;
        --raid-dir) raid_dir="$2"; shift ;;
        -h|--help) parley ;;
        -v|--version) echo "SubRaider v$VERSION"; exit 0 ;;
        *) echo -e "${red}Unknown order: $1${end}"; parley ;;
    esac
    shift
done

# Set default crew if none specified
[ ${#selected_crew[@]} -eq 0 ] && [ "$mutiny" == False ] && selected_crew=("${crew[@]}")

# Handle mutiny (exclude)
if [ "$mutiny" != False ]; then
    selected_crew=()
    for sailor in "${crew[@]}"; do
        [[ ! " ${mutiny_crew[@]} " =~ " ${sailor} " ]] && selected_crew+=("$sailor")
    done
fi

# Pirate flag
[ "$quiet_mode" == False ] && cat << "EOF"
${gold}
    ╔══════════════════════════════════════════════════════════════╗
    ║     ____        _        ____      _     _                   ║
    ║    / ___| _   _| |__    |  _ \ __ _(_) __| | ___ _ __        ║
    ║    \___ \| | | | '_ \   | |_) / _` | |/ _` |/ _ \ '__|       ║
    ║     ___) | |_| | |_) |  |  _ < (_| | | (_| |  __/ |          ║
    ║    |____/ \__,_|_.__/   |_| \_\__,_|_|\__,_|\___|_|          ║
    ║                                                              ║
    ║              ☠️  Pillage The Seven Digital Seas  ☠️           ║
    ║                    Version $VERSION - by gauravjha68535                ║
    ╚══════════════════════════════════════════════════════════════╝
${end}
EOF

# Launch the raid
main_raid
