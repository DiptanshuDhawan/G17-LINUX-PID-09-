#!/bin/bash

TARGET_DIR="."
VERBOSE=false
DRY_RUN=true
LOG_DIR="/var/log/permission_audit"
LOG_FILE="$LOG_DIR/permission_repair_$(date +%Y%m%d_%H%M%S).log"
SPECIFIC_USER=""
NEW_OWNER=""
NEW_GROUP=""

EXCLUDE_DIRS=()

print_banner() {
    local reset="\033[0m"
    local yellow="\033[1;33m"
    local cyan="\033[1;36m"
    local bold="\033[1m"

    echo -e "${yellow}        .--.
       |o_o |   ${cyan}TUX the Guardian${reset}
       |:_/ |
      //   \ \   🛡️
     (|     | )
    /'\\_   _/\\'
    \\___)=(___/${reset}

${bold}${cyan} ===[ Linux Permission Fixer ]=== ${reset}
     ${yellow}Secure. Scan. Fix.${reset}"
}



# === Logging Function ===
log() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "📄 [\033[0;36m$timestamp\033[0m] $message" | tee -a "$LOG_FILE"
}


# === 2.1 Disk Usage Analysis ===


display_disk_usage_by_user() {
    echo -e "\n📊 \033[1;34m=== Disk Usage by User ===\033[0m"

    if [ -n "$SPECIFIC_USER" ]; then
        # Specific user disk usage
        if id "$SPECIFIC_USER" &>/dev/null; then
            local size=$(find "$TARGET_DIR" -user "$SPECIFIC_USER" -type f -ls |
                        awk '{total += $7} END {printf "%.2f MB", total/(1024*1024)}')
            echo -e "👤 \033[1;33m$SPECIFIC_USER\033[0m: $size"
        else
            echo -e "❌ \033[1;31mUser '$SPECIFIC_USER' does not exist on this system.\033[0m"
        fi
    else
        # All users
        local users=$(find "$TARGET_DIR" -type f -exec stat -c "%U" {} \; | sort | uniq)
        for user in $users; do
            local size=$(find "$TARGET_DIR" -user "$user" -type f -ls |
                        awk '{total += $7} END {printf "%.2f MB", total/(1024*1024)}')
            echo -e "👤 \033[1;33m$user\033[0m: $size"
        done
    fi
}




# display_disk_usage_by_user() {
#     echo -e "\n📊 \033[1;34m=== Disk Usage by User ===\033[0m"
#     local users=$(find "$TARGET_DIR" -type f -exec stat -c "%U" {} \; | sort | uniq)

#     for user in $users; do
#         local size=$(find "$TARGET_DIR" -user "$user" -type f -ls |
#                     awk '{total += $7} END {printf "%.2f MB", total/(1024*1024)}')
#         echo -e "👤 \033[1;33m$user\033[0m: $size"
#     done
# }

# === 2.2 Permission Scanning ===
scan_risky_permissions() {
    local count=0
    echo -e "\n🔍 \033[1;31m=== Scanning for Risky Permissions ===\033[0m"
    while IFS= read -r -d $'\0' file; do
        ((count++))
        [ "$VERBOSE" = true ] && echo -e "⚠️  \033[1;31mWorld-writable file:\033[0m $file"
    done < <(find "$TARGET_DIR" -type f -perm -o=w -print0)

    return $count
}

# === 2.3 Permission Repair Engine ===
fix_permissions() {
    local fixed=0
    echo -e "\n🔧 \033[1;34m=== Fixing Risky Permissions ===\033[0m"

    # Fix files
    while IFS= read -r -d $'\0' file; do
        if [ "$DRY_RUN" = true ]; then
            echo -e "🟡 [DRY RUN] Would set file permission $DEFAULT_FILE_PERM: $file" | tee -a "$LOG_FILE"
        else
            chmod "$DEFAULT_FILE_PERM" "$file"
            echo -e "✅ [FIXED] Set file permission $DEFAULT_FILE_PERM: $file" >> "$LOG_FILE"
        fi
        ((fixed++))
    done < <(find "$TARGET_DIR" -type f -perm -o=w -print0)

    # Fix directories
    while IFS= read -r -d $'\0' dir; do
        if [ "$DRY_RUN" = true ]; then
            echo -e "🟡 [DRY RUN] Would set directory permission $DEFAULT_DIR_PERM: $dir" | tee -a "$LOG_FILE"
        else
            chmod "$DEFAULT_DIR_PERM" "$dir"
            echo -e "✅ [FIXED] Set directory permission $DEFAULT_DIR_PERM: $dir" >> "$LOG_FILE"
        fi
        ((fixed++))
    done < <(find "$TARGET_DIR" -type d -perm -o=w -print0)

    return $fixed
}



# === 2.4 Argument Parsing ===
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)
                TARGET_DIR="$2"
                shift 2
                ;;
            -b|--banner)
                print_banner
                exit 0
                ;;
            -f|--fix)
                DRY_RUN=false
                shift
                ;;
            -u|--user)
                SPECIFIC_USER="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --file-perm)
                DEFAULT_FILE_PERM="$2"
                shift 2
                ;;
            --owner)
                NEW_OWNER="$2"
                shift 2
                ;;

            --group)
                NEW_GROUP="$2"
                shift 2
                ;;

            --dir-perm)
                DEFAULT_DIR_PERM="$2"
                shift 2
                ;;
            -h|--help)
    echo -e "\n🛠️  \033[1;36mPermission Audit & Repair Script\033[0m"
    echo -e "This script scans a directory for risky permissions (world-writable files/directories),"
    echo -e "displays disk usage per user, and optionally fixes the permissions."
    echo -e "\n\033[1;34mUsage:\033[0m"
    echo -e "  $0 [OPTIONS]\n"
    echo -e "\033[1;33mOptions:\033[0m"
    echo -e "  -t, --target <directory>       Target directory to audit (default: current directory '.')"
    echo -e "  -f, --fix                      Apply fixes to risky permissions (default: DRY RUN mode)"
    echo -e "  -u, --user <username>          Show disk usage for a specific user only"
    echo -e "  -v, --verbose                  Enable verbose output (shows each risky file during scan)"
    echo -e "      --file-perm <mode>         Set default permission for risky files (e.g., 644)"
    echo -e "      --dir-perm <mode>          Set default permission for risky directories (e.g., 755)"
    echo -e "  -h, --help                     Display this help message and exit"
    echo -e "\n\033[1;33mOther Information:\033[0m"
    echo -e "  📁 Log files are saved under /var/log/permission_audit with timestamps."
    echo -e "  🔍 Risky permissions are defined as world-writable (others have write access)."
    echo -e "  🛡️  Fixing permissions helps improve system security and file integrity."
    echo -e "  📝 Use with caution when running with --fix, especially on system directories.\n"
    echo -e "      --owner <username>         Change ownership of risky items to this user"
    echo -e "      --group <groupname>        Change group of risky items to this group"

    exit 0
    ;;
            -hg|--helpforgui)
    echo -e "  -t, --target <directory>       Target directory to audit (default: current directory '.')"
    echo -e "  -f, --fix                      Apply fixes to risky permissions (default: DRY RUN mode)"
    echo -e "  -u, --user <username>          Show disk usage for a specific user only"
    echo -e "  -v, --verbose                  Enable verbose output (shows each risky file during scan)"
    echo -e "      --file-perm <mode>         Set default permission for risky files (e.g., 644)"
    echo -e "      --dir-perm <mode>          Set default permission for risky directories (e.g., 755)"
    echo -e "      --owner <username>         Change ownership of risky items to this user"
    echo -e "      --group <groupname>        Change group of risky items to this group"

    exit 0
    ;;

            *)
                echo "❌ Unknown option: $1"
                exit 1
                ;;
        esac
    done
}





# === Default Fix Configuration ===
DEFAULT_FILE_PERM="644"
DEFAULT_DIR_PERM="755"

get_user_permission_preferences() {
    echo -e "\n⚙️  \033[1;36mDefault Permissions Configuration\033[0m"
    echo -e "Current default file permission: \033[1;33m$DEFAULT_FILE_PERM\033[0m"
    read -p "Enter new default file permission (or press Enter to keep): " input_file_perm
    if [[ "$input_file_perm" =~ ^[0-7]{3,4}$ ]]; then
        DEFAULT_FILE_PERM="$input_file_perm"
    fi

    echo -e "Current default directory permission: \033[1;33m$DEFAULT_DIR_PERM\033[0m"
    read -p "Enter new default directory permission (or press Enter to keep): " input_dir_perm
    if [[ "$input_dir_perm" =~ ^[0-7]{3,4}$ ]]; then
        DEFAULT_DIR_PERM="$input_dir_perm"
    fi
}


change_ownership() {
    local changed=0
    echo -e "\n👤 \033[1;34m=== Changing Ownership ===\033[0m"

    find "$TARGET_DIR" \( -type f -o -type d \) -perm -o=w -print0 | while IFS= read -r -d $'\0' item; do
        local change_cmd="chown"
        [ -n "$NEW_OWNER" ] && change_cmd+=" $NEW_OWNER"
        [ -n "$NEW_GROUP" ] && change_cmd+=".$NEW_GROUP"
        change_cmd+=" \"$item\""

        if [ "$DRY_RUN" = true ]; then
            echo -e "🟡 [DRY RUN] Would run: $change_cmd" | tee -a "$LOG_FILE"
        else
            eval $change_cmd
            echo -e "✅ [CHOWN] $change_cmd" >> "$LOG_FILE"
        fi
        ((changed++))
    done
}




main() {
    # If no arguments are passed, show banner and help
    if [ $# -eq 0 ]; then
        print_banner
        
        echo -e "\n🛠️  \033[1;36mPermission Audit & Repair Script\033[0m"
        echo -e "This script scans a directory for risky permissions (world-writable files/directories),"
        echo -e "displays disk usage per user, and optionally fixes the permissions."
        echo -e "\n\033[1;34mUsage:\033[0m"
        echo -e "  $0 [OPTIONS]\n"
        echo -e "\033[1;33mOptions:\033[0m"
        echo -e "  -t, --target <directory>       Target directory to audit (default: current directory '.')"
        echo -e "  -f, --fix                      Apply fixes to risky permissions (default: DRY RUN mode)"
        echo -e "  -u, --user <username>          Show disk usage for a specific user only"
        echo -e "  -v, --verbose                  Enable verbose output (shows each risky file during scan)"
        echo -e "      --file-perm <mode>         Set default permission for risky files (e.g., 644)"
        echo -e "      --dir-perm <mode>          Set default permission for risky directories (e.g., 755)"
        echo -e "  -h, --help                     Display this help message and exit"
        echo -e "  -b, --banner                   Display the banner"
        echo -e "\n\033[1;33mOther Information:\033[0m"
        echo -e "  📁 Log files are saved under /var/log/permission_audit with timestamps."
        echo -e "  🔍 Risky permissions are defined as world-writable (others have write access)."
        echo -e "  🛡️  Fixing permissions helps improve system security and file integrity."
        echo -e "  📝 Use with caution when running with --fix, especially on system directories.\n"
        echo -e "      --owner <username>         Change ownership of risky items to this user"
        echo -e "      --group <groupname>        Change group of risky items to this group"

        exit 0
    fi

    parse_arguments "$@"
    
    
    print_banner
    
    # Ensure log directory exists
    mkdir -p "$LOG_DIR" 2>/dev/null || {
        echo "❌ Cannot create log directory $LOG_DIR. Check permissions."
        exit 1
    }

    log "Starting permission audit on: $TARGET_DIR"
    [ "$DRY_RUN" = true ] && log "Dry run enabled. No changes will be made."
    [ "$VERBOSE" = true ] && log "Verbose mode on."

    display_disk_usage_by_user

    scan_risky_permissions
    local found=$?
    log "Total risky items found: $found"

    fix_permissions
    local fixed=$?
    log "Total risky items handled: $fixed"

   if [[ -n "$NEW_OWNER" || -n "$NEW_GROUP" ]]; then
        change_ownership         # 3. Change ownership if options provided
    fi

    echo -e "\n✅ \033[1;32mAudit complete. Log saved to:\033[0m 📁 $LOG_FILE"
}


main "$@"