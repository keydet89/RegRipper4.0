#-----------------------------------------------------------
# capabilityaccessmgr.pl
# Plugin for RegRipper 4.0 - CapabilityAccessManager Analysis
# 
# Extracts microphone, webcam, and location usage data from Windows 
# CapabilityAccessManager registry keys for forensic analysis.
#
# Registry locations:
# - SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore (Global)
# - NTUSER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore (User)
#
# Supported capabilities: microphone, webcam, location
#
# Author: Sujay Adkesar
# Version: 3.3
# Date: 2025-08-17
#-----------------------------------------------------------
package capabilityaccessmgr;
use strict;

my %config = (
    hive          => "Software,NTUSER",
    hasShortDescr => 1,
    hasDescr      => 1,
    hasRefs       => 1,
    osmask        => 22,
    version       => 20250817
);

sub getConfig{ return %config }

sub getShortDescr {
    return "Extracts CapabilityAccessManager data (microphone, webcam, location usage)";
}

sub getDescr{
    return "Extracts detailed application usage data from CapabilityAccessManager registry keys. ".
           "This includes microphone, webcam, and location access data with timestamps, ".
           "application paths, and session durations. Useful for tracking privacy-sensitive ".
           "device usage and detecting unauthorized access or malware activity.\n\n".
           "USAGE: Individual app permissions stored in NTUSER.DAT hive. ".
           "Run against both SOFTWARE and NTUSER.DAT hives for complete analysis.";
}

sub getRefs {
    my %refs = (
        "Windows Privacy Controls" => 
            "https://docs.microsoft.com/en-us/windows/privacy/",
        "CapabilityAccessManager Forensics" => 
            "https://cyberengage.org/post/registry-system-configiuration-tracking-microphone-and-camera-usage-in-windows-program-execution",
        "MITRE ATT&CK T1123" => "Audio Capture - https://attack.mitre.org/techniques/T1123/",
        "MITRE ATT&CK T1125" => "Video Capture - https://attack.mitre.org/techniques/T1125/"
    );
    return %refs;
}

sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
    my $class = shift;
    my $hive = shift;
    
    ::logMsg("Launching capabilityaccessmgr v.".$VERSION);
    ::rptMsg("capabilityaccessmgr v.".$VERSION);
    ::rptMsg("(".$config{hive}.") ".getShortDescr());
    ::rptMsg("Analysis Tips: Run against both SOFTWARE and NTUSER.DAT for complete view");
    ::rptMsg("");
    
    my $root_key;
    eval {
        $root_key = Parse::Win32Registry->new($hive)->get_root_key;
    };
    if ($@) {
        ::rptMsg("ERROR: Could not access registry hive - ".$@);
        return;
    }

    # Determine which hive we're analyzing - fix uninitialized warning
    my $hive_type = "Unknown";
    if (defined $hive && $hive =~ /SOFTWARE/i) {
        $hive_type = "SOFTWARE";
        ::rptMsg("[INFO] Analyzing SOFTWARE hive (system-wide capability settings)");
    } elsif (defined $hive && $hive =~ /NTUSER/i) {
        $hive_type = "NTUSER";
        ::rptMsg("[INFO] Analyzing NTUSER.DAT hive (user-specific app permissions)");
    }
    ::rptMsg("");

    # Define the capabilities to analyze
    my @capabilities = ("microphone", "webcam", "location");
    my $capability_base_path = "Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore";
    
    # Try both possible registry paths
    my @base_paths = (
        "Software\\$capability_base_path",  # NTUSER hive
        $capability_base_path               # SOFTWARE hive
    );
    
    my $found_data = 0;
    
    foreach my $base_path (@base_paths) {
        eval {
            my $consent_store = $root_key->get_subkey($base_path);
            if (defined $consent_store) {
                ::rptMsg("[+] Found CapabilityAccessManager data at: $base_path");
                ::rptMsg("");
                
                foreach my $capability (@capabilities) {
                    analyze_capability($consent_store, $capability, $hive_type);
                }
                $found_data = 1;
            }
        };
    }
    
    if (!$found_data) {
        ::rptMsg("[-] No CapabilityAccessManager data found in this hive");
        if ($hive_type eq "SOFTWARE") {
            ::rptMsg("[TIP] User application permissions are in NTUSER.DAT hive");
            ::rptMsg("      Try: rip.exe -r NTUSER.DAT -p capabilityaccessmgr");
        }
    }
    
    ::rptMsg("");
    ::rptMsg("Analysis Tips:");
    ::rptMsg("- SOFTWARE hive: Global capability settings");
    ::rptMsg("- NTUSER.DAT hive: Individual application permissions and usage");
    ::rptMsg("- Check NonPackaged entries for potential unauthorized applications");
    ::rptMsg("- Verify application paths match expected installation locations");
    ::rptMsg("- Cross-reference with Windows event logs for complete timeline");
}

sub analyze_capability {
    my ($consent_store, $capability, $hive_type) = @_;
    
    ::rptMsg("");
    ::rptMsg(uc($capability)." CAPABILITY ANALYSIS");
    ::rptMsg("="x50);
    
    eval {
        my $cap_key = $consent_store->get_subkey($capability);
        if (!defined $cap_key) {
            ::rptMsg("No $capability capability data found");
            return;
        }
        
        # Get global settings
        eval {
            my $value_default = $cap_key->get_value("Value");
            if (defined $value_default) {
                my $value_data = $value_default->get_data();
                my $status = decode_capability_status($value_data);
                ::rptMsg("Global Setting: $capability access is $status");
            }
        };
        
        # Get key last write time for context
        my $key_timestamp = $cap_key->get_timestamp();
        ::rptMsg("Key Last Modified: ".convert_epoch_to_utc_string($key_timestamp));
        
        # Process application entries
        my @subkeys;
        eval {
            @subkeys = $cap_key->get_list_of_subkeys();
        };
        
        if (@subkeys == 0) {
            ::rptMsg("No application entries found for $capability");
            if (defined $hive_type && $hive_type eq "SOFTWARE") {
                ::rptMsg("[INFO] User app permissions typically in NTUSER.DAT");
            }
            return;
        }
        
        ::rptMsg("");
        ::rptMsg("Application Permissions and Usage:");
        ::rptMsg("-"x40);
        
        my $app_count = 0;
        my $apps_with_usage = 0;
        
        foreach my $app_key (@subkeys) {
            next unless defined $app_key;
            my $app_name = $app_key->get_name() || "Unknown";
            $app_count++;
            
            my $has_usage = analyze_application($app_key, $capability, $app_count);
            $apps_with_usage++ if $has_usage;
        }
        
        ::rptMsg("");
        ::rptMsg("Summary: $app_count applications have $capability access configured");
        ::rptMsg("         $apps_with_usage applications have recorded usage timestamps");
        
    };
    if ($@) {
        ::rptMsg("ERROR analyzing $capability: ".$@);
    }
}

sub analyze_application {
    my ($app_key, $capability, $app_num) = @_;
    my $app_name = defined $app_key ? ($app_key->get_name() || "Unknown") : "Unknown";
    my $has_usage_data = 0;
    
    ::rptMsg("");
    ::rptMsg("[$app_num] $app_name");
    
    # Get key last write time
    my $key_timestamp = $app_key->get_timestamp();
    ::rptMsg("    Key LastWrite: ".convert_epoch_to_utc_string($key_timestamp));
    
    # Get application permission status
    eval {
        my $value = $app_key->get_value("Value");
        if (defined $value) {
            my $value_data = $value->get_data();
            my $permission_status = decode_capability_status($value_data);
            ::rptMsg("    Permission: $permission_status");
        } else {
            ::rptMsg("    Permission: Not configured");
        }
    };
    
    # Get all timestamp values
    my %timestamps = get_all_timestamps($app_key);
    
    # Display usage timestamps if they exist
    if (defined $timestamps{"LastUsedTimeStart"} && $timestamps{"LastUsedTimeStart"} > 0) {
        my $start_time = convert_epoch_to_utc_string($timestamps{"LastUsedTimeStart"});
        ::rptMsg("    Last Used Start: $start_time");
        $has_usage_data = 1;
        
        if (defined $timestamps{"LastUsedTimeStop"} && $timestamps{"LastUsedTimeStop"} > 0) {
            my $stop_time = convert_epoch_to_utc_string($timestamps{"LastUsedTimeStop"});
            ::rptMsg("    Last Used End:   $stop_time");
            
            # Calculate duration if both timestamps are valid
            if ($timestamps{"LastUsedTimeStop"} > $timestamps{"LastUsedTimeStart"}) {
                my $duration_seconds = $timestamps{"LastUsedTimeStop"} - $timestamps{"LastUsedTimeStart"};
                my $duration_formatted = format_duration($duration_seconds);
                ::rptMsg("    Session Duration: $duration_formatted");
            }
        }
    }
    
    # Display other timestamps
    foreach my $field (sort keys %timestamps) {
        next unless defined $field;
        next if ($field eq "LastUsedTimeStart" || $field eq "LastUsedTimeStop");
        if (defined $timestamps{$field} && $timestamps{$field} > 0) {
            my $formatted_time = convert_epoch_to_utc_string($timestamps{$field});
            ::rptMsg("    $field: $formatted_time");
        }
    }
    
    # Show additional registry values
    eval {
        my @value_names = $app_key->get_list_of_values();
        foreach my $value_name (@value_names) {
            next unless defined $value_name;
            next if ($value_name eq "Value" || (defined $value_name && $value_name =~ /time/i));
            
            my $value = $app_key->get_value($value_name);
            if (defined $value) {
                my $data = $value->get_data();
                if (defined $data) {
                    ::rptMsg("    $value_name: $data");
                }
            }
        }
    };
    
    # Handle NonPackaged applications
    if (defined $app_name && $app_name eq "NonPackaged") {
        ::rptMsg("    [ALERT] NonPackaged applications detected");
        ::rptMsg("            Verify legitimacy of desktop applications accessing $capability");
        
        eval {
            my @nonpackaged_apps = $app_key->get_list_of_subkeys();
            foreach my $np_app (@nonpackaged_apps) {
                next unless defined $np_app;
                analyze_nonpackaged_app($np_app, $capability);
            }
        };
    }
    
    # Security analysis
    check_security_concerns($app_key, $app_name, $capability, \%timestamps);
    
    return $has_usage_data;
}

sub analyze_nonpackaged_app {
    my ($np_app_key, $capability) = @_;
    my $app_hash = defined $np_app_key ? ($np_app_key->get_name() || "Unknown") : "Unknown";
    
    # Decode application path
    my $decoded_path = $app_hash;
    if (defined $decoded_path) {
        $decoded_path =~ s/#/\\/g;
    }
    
    ::rptMsg("");
    ::rptMsg("    >> Traditional App: ".($decoded_path || $app_hash));
    
    # Get key timestamp
    my $key_timestamp = $np_app_key->get_timestamp();
    ::rptMsg("       Key LastWrite: ".convert_epoch_to_utc_string($key_timestamp));
    
    # Get usage timestamps
    my %timestamps = get_all_timestamps($np_app_key);
    
    if (defined $timestamps{"LastUsedTimeStart"} && $timestamps{"LastUsedTimeStart"} > 0) {
        my $start_time = convert_epoch_to_utc_string($timestamps{"LastUsedTimeStart"});
        ::rptMsg("       Last Used: $start_time");
        
        if (defined $timestamps{"LastUsedTimeStop"} && $timestamps{"LastUsedTimeStop"} > 0) {
            my $stop_time = convert_epoch_to_utc_string($timestamps{"LastUsedTimeStop"});
            my $duration_seconds = $timestamps{"LastUsedTimeStop"} - $timestamps{"LastUsedTimeStart"};
            if ($duration_seconds > 0) {
                my $duration_formatted = format_duration($duration_seconds);
                ::rptMsg("       Duration: $duration_formatted");
            }
        }
    } else {
        ::rptMsg("       Last Used: No usage recorded");
    }
    
    # Check for suspicious paths
    if (defined $decoded_path && $decoded_path =~ /(temp|tmp|appdata.*temp|users.*downloads)/i) {
        ::rptMsg("       [WARNING] Suspicious temporary location");
    }
}

sub get_all_timestamps {
    my ($key) = @_;
    my %timestamps;
    
    return %timestamps unless defined $key;
    
    my @timestamp_fields = ("LastUsedTimeStart", "LastUsedTimeStop", "LastSetTime");
    
    foreach my $field (@timestamp_fields) {
        next unless defined $field;
        eval {
            my $time_value = $key->get_value($field);
            if (defined $time_value) {
                my $raw_data = $time_value->get_data();
                if (defined $raw_data) {
                    my $unix_time = convert_filetime_to_unix($raw_data);
                    $timestamps{$field} = $unix_time if $unix_time > 0;
                }
            }
        };
    }
    
    return %timestamps;
}

sub convert_filetime_to_unix {
    my ($filetime_data) = @_;
    
    return 0 unless defined $filetime_data;
    
    my $filetime = 0;
    
    # Handle different data formats
    if (length($filetime_data) == 8) {
        # 8-byte FILETIME (REG_QWORD) - parse as little-endian
        my @bytes = unpack("C8", $filetime_data);
        for (my $i = 0; $i < 8; $i++) {
            $filetime += $bytes[$i] << ($i * 8);
        }
    } elsif (defined $filetime_data && $filetime_data =~ /^\d+$/) {
        # Already numeric
        $filetime = int($filetime_data);
    } else {
        return 0;
    }
    
    return 0 if $filetime <= 0;
    
    # Convert FILETIME to Unix timestamp
    # FILETIME: 100-nanosecond intervals since January 1, 1601
    # Unix: seconds since January 1, 1970
    my $unix_timestamp = ($filetime / 10_000_000) - 11_644_473_600;
    
    # Validate timestamp range (1970 to 2100)
    return ($unix_timestamp > 0 && $unix_timestamp < 4_102_444_800) ? int($unix_timestamp) : 0;
}

sub convert_epoch_to_utc_string {
    my ($epoch) = @_;
    
    return "Never used or not recorded" if (!defined($epoch) || $epoch <= 0);
    
    my ($sec, $min, $hour, $mday, $mon, $year) = gmtime($epoch);
    return sprintf("%04d-%02d-%02d %02d:%02d:%02d UTC", $year+1900, $mon+1, $mday, $hour, $min, $sec);
}

sub check_security_concerns {
    my ($app_key, $app_name, $capability, $timestamps_ref) = @_;
    
    # Check for extended usage sessions
    if (defined $timestamps_ref && 
        defined $timestamps_ref->{"LastUsedTimeStart"} && 
        defined $timestamps_ref->{"LastUsedTimeStop"}) {
        my $duration = $timestamps_ref->{"LastUsedTimeStop"} - $timestamps_ref->{"LastUsedTimeStart"};
        if ($duration > 14400) {  # > 4 hours
            ::rptMsg("    [ALERT] Extended $capability usage session detected (>4 hours)");
        }
    }
    
    # Check for suspicious application patterns - fix for uninitialized value warning
    if (defined $app_name && $app_name =~ /(temp|tmp|\d{8,}|unknown|test)/i) {
        ::rptMsg("    [WARNING] Suspicious application name pattern");
    }
}

sub decode_capability_status {
    my ($value) = @_;
    
    return "Unknown" unless defined $value;
    
    if ($value eq "Allow") {
        return "Allowed";
    } elsif ($value eq "Deny") {
        return "Denied";
    } elsif ($value eq "Prompt") {
        return "Prompt User";
    } else {
        return "Unknown ($value)";
    }
}

sub format_duration {
    my ($seconds) = @_;
    
    return "0s" if !defined($seconds) || $seconds <= 0;
    
    my $hours = int($seconds / 3600);
    my $minutes = int(($seconds % 3600) / 60);
    my $remaining_seconds = int($seconds % 60);
    
    my @parts;
    push @parts, "${hours}h" if $hours > 0;
    push @parts, "${minutes}m" if $minutes > 0;
    push @parts, "${remaining_seconds}s" if $remaining_seconds > 0 || @parts == 0;
    
    return join(" ", @parts);
}

1;
