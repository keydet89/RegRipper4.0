#-----------------------------------------------------------
# radar.pl - Bulletproof version with comprehensive detection
# Plugin to analyze RADAR HeapLeakDetection DiagnosedApplications
# 
# 
# Category: Program Execution
#-----------------------------------------------------------
package radar;
use strict;
# Removed 'use warnings' to prevent Perl engine warnings

my %config = (hive          => "Software",
              hasShortDescr => 1,
              hasDescr      => 1,
              hasRefs       => 0,
              MITRE         => "T1055,T1106,T1547",
              category      => "program execution");

sub getConfig{return %config}
sub getShortDescr {
    return "RADAR - Analyze HeapLeakDetection DiagnosedApplications registry key";
}
sub getDescr{
    return "Analyzes Windows RADAR (Resource Exhaustion Detection and Resolution) ".
           "HeapLeakDetection DiagnosedApplications registry key to identify ".
           "executables that triggered memory leak detection (5%+ RAM usage)";
}
sub getHive {return $config{hive};}
sub getVersion {return "1.0";}

my $VERSION = getVersion();

sub pluginmain {
    my $class = shift;
    my $hive = shift;
    ::logMsg("Launching radar v.".$VERSION);
    ::rptMsg("radar v.".$VERSION);
    ::rptMsg("(".$config{hive}.") ".getShortDescr());
    ::rptMsg("MITRE: ".$config{MITRE});
    ::rptMsg("");
    
    my $reg = Parse::Win32Registry->new($hive);
    my $root_key = $reg->get_root_key;
    
    # Target the specific RADAR registry path
    my $radar_path = "Microsoft\\RADAR\\HeapLeakDetection\\DiagnosedApplications";
    
    ::rptMsg("RADAR HeapLeakDetection Analysis");
    ::rptMsg("=" x 50);
    ::rptMsg("Registry Path: HKLM\\SOFTWARE\\$radar_path");
    ::rptMsg("");
    
    eval {
        my $radar_key = $root_key->get_subkey($radar_path);
        
        if ($radar_key) {
            ::rptMsg("SUCCESS: RADAR HeapLeakDetection key found!");
            ::rptMsg("");
            
            # Get ALL subkeys - this is the critical part
            my @app_subkeys;
            eval {
                @app_subkeys = $radar_key->get_list_of_subkeys();
            };
            
            my $total_apps = scalar(@app_subkeys);
            
            if ($total_apps > 0) {
                ::rptMsg("Applications Diagnosed by RADAR (Memory Usage >= 5% RAM):");
                ::rptMsg("-" x 65);
                ::rptMsg("Total diagnosed applications: $total_apps");
                ::rptMsg("");
                
                my @apps_with_timestamps = ();
                my @apps_without_timestamps = ();
                
                # Process EVERY subkey found
                foreach my $app_key (@app_subkeys) {
                    my $app_name = "";
                    eval {
                        $app_name = $app_key->get_name();
                    };
                    
                    # Skip if we can't get the name
                    next unless $app_name && length($app_name) > 0;
                    
                                        
                    my %app_data = (name => $app_name);
                    my $has_timestamp = 0;
                    my @values = ();
                    
                    # Try to get values - this might fail or return empty array
                    eval {
                        @values = $app_key->get_list_of_values();
                    };
                    
                    my $value_count = scalar(@values);
                                        
                    # Process values if they exist
                    if (@values) {
                        foreach my $val (@values) {
                            eval {
                                my $value_name = $val->get_name();
                                my $value_data = $val->get_data();
                                
                                if ($value_name && $value_name eq "LastDetectionTime") {
                                    if ($value_data && length($value_data) > 0) {
                                        $app_data{last_detection} = convertFiletime($value_data);
                                        $app_data{last_detection_raw} = getFiletimeRaw($value_data);
                                        $has_timestamp = 1;
                                    }
                                } elsif ($value_name && $value_name eq "FirstDetectionTime") {
                                    if ($value_data && length($value_data) > 0) {
                                        $app_data{first_detection} = convertFiletime($value_data);
                                    }
                                } elsif ($value_name && $value_name eq "DetectionCount") {
                                    $app_data{detection_count} = $value_data if defined $value_data;
                                } elsif ($value_name && $value_name eq "ExecutionTime") {
                                    if ($value_data && length($value_data) > 0) {
                                        $app_data{execution_time} = convertFiletime($value_data);
                                    }
                                } elsif ($value_name && $value_name eq "LastExecutionTime") {
                                    if ($value_data && length($value_data) > 0) {
                                        $app_data{last_execution} = convertFiletime($value_data);
                                    }
                                } elsif ($value_name && $value_name eq "FirstExecutionTime") {
                                    if ($value_data && length($value_data) > 0) {
                                        $app_data{first_execution} = convertFiletime($value_data);
                                    }
                                } elsif ($value_name) {
                                    # Store other values
                                    $app_data{$value_name} = $value_data if defined $value_data;
                                }
                            };
                        }
                    }
                    
                    # ALWAYS add the application to one of the arrays
                    if ($has_timestamp) {
                        $app_data{last_detection_raw} = $app_data{last_detection_raw} || 0;
                        push @apps_with_timestamps, \%app_data;
                    } else {
                        # This is where we catch entries without timestamps
                        $app_data{last_detection} = "No timestamp available";
                        $app_data{last_detection_raw} = 0;
                        
                        if (@values > 0) {
                            $app_data{registry_status} = "Registry key has values but no timestamp";
                        } else {
                            $app_data{registry_status} = "Empty registry key (no values)";
                        }
                        
                        push @apps_without_timestamps, \%app_data;
                    }
                }
                
                # Sort apps with timestamps
                @apps_with_timestamps = sort { 
                    ($b->{last_detection_raw} || 0) <=> ($a->{last_detection_raw} || 0) 
                } @apps_with_timestamps;
                
                # Display results
                displayResults(\@apps_with_timestamps, \@apps_without_timestamps);
                
                # Summary analysis
                ::rptMsg("RADAR Analysis Summary:");
                ::rptMsg("-" x 25);
                my @all_apps = (@apps_with_timestamps, @apps_without_timestamps);
                analyzeRADARResults(\@all_apps, scalar(@apps_with_timestamps), scalar(@apps_without_timestamps));
                
            } else {
                ::rptMsg("No application subkeys found in DiagnosedApplications.");
                ::rptMsg("This could indicate:");
                ::rptMsg("- No applications have triggered RADAR detection");
                ::rptMsg("- RADAR is disabled on this system");
                ::rptMsg("- Registry key has been completely cleaned");
                ::rptMsg("");
            }
            
            
        } else {
            ::rptMsg("ERROR: RADAR HeapLeakDetection key not found!");
            ::rptMsg("");
        }
        
    };
    
    if ($@) {
        ::rptMsg("Error accessing RADAR registry key: $@");
        ::rptMsg("");
    }
    
    # Forensic context
    ::rptMsg("Forensic Context:");
    ::rptMsg("-" x 17);
    ::rptMsg("- RADAR detects applications consuming >= 5% of total physical RAM");
    ::rptMsg("- Detection indicates significant memory usage/potential memory leaks");
    ::rptMsg("- Presence in this key confirms executable was run on the system");
    ::rptMsg("- LastDetectionTime shows when high memory usage was detected");
    ::rptMsg("- ExecutionTime values show when applications were actually run");
    ::rptMsg("- Entries without timestamps still indicate RADAR flagged the application");
    ::rptMsg("- Empty registry keys may indicate interrupted detections or cleanup");
    ::rptMsg("- This artifact persists across reboots and application exits");
    ::rptMsg("");
}

sub displayResults {
    my ($with_timestamps_ref, $without_timestamps_ref) = @_;
    my @apps_with_timestamps = @$with_timestamps_ref;
    my @apps_without_timestamps = @$without_timestamps_ref;
    
    my $count = 1;
    
    if (@apps_with_timestamps > 0) {
        ::rptMsg("Applications with Detection Timestamps:");
        ::rptMsg("-" x 42);
        
        foreach my $app (@apps_with_timestamps) {
            ::rptMsg("[$count] " . ($app->{name} || "Unknown"));
            ::rptMsg("    Last Detection Time: " . ($app->{last_detection} || "Unknown"));
            
            # Show execution times if available
            foreach my $field (qw(execution_time last_execution first_execution first_detection detection_count)) {
                if ($app->{$field}) {
                    my $label = ucfirst($field);
                    $label =~ s/_/ /g;
                    ::rptMsg("    $label: " . $app->{$field});
                }
            }
            
            # Show any additional values
            foreach my $key (sort keys %$app) {
                next if $key =~ /^(name|last_detection|last_detection_raw|execution_time|last_execution|first_execution|first_detection|detection_count)$/;
                if (defined $app->{$key} && $app->{$key} ne "") {
                    ::rptMsg("    $key: " . $app->{$key});
                }
            }
            
            ::rptMsg("");
            $count++;
        }
    }
    
    # Display apps without timestamps - THIS IS THE CRITICAL SECTION
    if (@apps_without_timestamps > 0) {
        ::rptMsg("Applications without Detection Timestamps:");
        ::rptMsg("-" x 45);
        ::rptMsg("(These entries exist in RADAR registry but lack timestamp data)");
        ::rptMsg("");
        
        foreach my $app (@apps_without_timestamps) {
            ::rptMsg("[$count] " . ($app->{name} || "Unknown"));
            ::rptMsg("    Last Detection Time: " . ($app->{last_detection} || "No timestamp"));
            
            if ($app->{registry_status}) {
                ::rptMsg("    Registry Status: " . $app->{registry_status});
            }
            
            ::rptMsg("    Possible reasons for missing timestamp:");
            ::rptMsg("      - RADAR detection interrupted before completion");
            ::rptMsg("      - Registry corruption or partial cleanup");
            ::rptMsg("      - Different RADAR detection mode");
            ::rptMsg("      - System shutdown during detection process");
            ::rptMsg("      - Manual registry editing or cleanup tools");
            
            # Show any available values
            my $has_other_data = 0;
            foreach my $key (sort keys %$app) {
                next if $key =~ /^(name|last_detection|last_detection_raw|registry_status)$/;
                if (defined $app->{$key} && $app->{$key} ne "") {
                    if (!$has_other_data) {
                        ::rptMsg("    Available Data:");
                        $has_other_data = 1;
                    }
                    ::rptMsg("      $key: " . $app->{$key});
                }
            }
            
            if (!$has_other_data) {
                ::rptMsg("    Additional Data: None available (empty registry key)");
            }
            
            ::rptMsg("    Evidence: Application was flagged by RADAR (timestamp missing/corrupted)");
            ::rptMsg("    Forensic Value: Registry key existence confirms RADAR detection occurred");
            ::rptMsg("");
            $count++;
        }
    }
}

sub analyzeRADARResults {
    my ($apps_ref, $with_timestamps, $without_timestamps) = @_;
    return unless $apps_ref && @$apps_ref;
    
    my @apps = @$apps_ref;
    
    # Ultra-safe categorization without any regex or uninitialized variable warnings
    my %categories = (
        'System' => [],
        'Browsers' => [],
        'Development' => [],
        'Games' => [],
        'Media' => [],
        'Security' => [],
        'Forensic Tools' => [],
        'Other' => []
    );
    
    foreach my $app (@apps) {
        next unless $app && ref($app) eq 'HASH' && $app->{name};
        
        my $name = $app->{name};
        next unless $name && length($name) > 0;
        
        my $name_safe = lc($name);
        my $category = 'Other';  # Safe default
        
        # Use substr and index for ultra-safe string matching
        if (index($name_safe, 'system') >= 0 || index($name_safe, 'explorer') >= 0 ||
            index($name_safe, 'tiworker') >= 0 || index($name_safe, 'searchfilterhost') >= 0) {
            $category = 'System';
        } elsif (index($name_safe, 'chrome') >= 0 || index($name_safe, 'firefox') >= 0 ||
                 index($name_safe, 'edge') >= 0 || index($name_safe, 'brave') >= 0 ||
                 index($name_safe, 'msedge') >= 0) {
            $category = 'Browsers';
        } elsif (index($name_safe, 'code') >= 0 || index($name_safe, 'python') >= 0 ||
                 index($name_safe, 'java') >= 0 || index($name_safe, 'git') >= 0) {
            $category = 'Development';
        } elsif (index($name_safe, 'game') >= 0 || index($name_safe, 'steam') >= 0) {
            $category = 'Games';
        } elsif (index($name_safe, 'photo') >= 0 || index($name_safe, 'video') >= 0 ||
                 index($name_safe, 'vlc') >= 0) {
            $category = 'Media';
        } elsif (index($name_safe, 'mcshield') >= 0 || index($name_safe, 'defender') >= 0 ||
                 index($name_safe, 'security') >= 0) {
            $category = 'Security';
        } elsif (index($name_safe, 'mftecmd') >= 0 || index($name_safe, 'forensic') >= 0) {
            $category = 'Forensic Tools';
        }
        
        push @{$categories{$category}}, $name;
    }
    
    # Display categories safely
    foreach my $category (sort keys %categories) {
        my $apps_in_category = $categories{$category};
        if ($apps_in_category && @$apps_in_category > 0) {
            ::rptMsg("$category Applications: " . scalar(@$apps_in_category));
            foreach my $app (@$apps_in_category) {
                ::rptMsg("  - $app") if $app;
            }
        }
    }
    
    ::rptMsg("");
    ::rptMsg("Detection Statistics:");
    ::rptMsg("- Applications with timestamps: " . ($with_timestamps || 0));
    ::rptMsg("- Applications without timestamps: " . ($without_timestamps || 0));
    ::rptMsg("- Total RADAR detections: " . scalar(@apps));
    
    if ($without_timestamps && $without_timestamps > 0) {
        ::rptMsg("- IMPORTANT: " . $without_timestamps . " applications exist in registry without timestamps");
        ::rptMsg("- These represent interrupted or corrupted RADAR detections");
        ::rptMsg("- Registry key existence still confirms the application triggered RADAR");
    }
    
    
    if ($with_timestamps && $with_timestamps > 0) {
        ::rptMsg("");
        ::rptMsg("Timeline Analysis:");
        my @apps_with_time = grep { 
            $_ && $_->{last_detection_raw} && $_->{last_detection_raw} > 0 
        } @apps;
        
        if (@apps_with_time > 0) {
            my $most_recent = $apps_with_time[0];
            my $oldest = $apps_with_time[-1];
            
            if ($most_recent && $oldest) {
                ::rptMsg("- Most recent detection: " . ($most_recent->{name} || "Unknown") . 
                        " (" . ($most_recent->{last_detection} || "Unknown") . ")");
                ::rptMsg("- Oldest detection: " . ($oldest->{name} || "Unknown") . 
                        " (" . ($oldest->{last_detection} || "Unknown") . ")");
                ::rptMsg("- Detection timespan covers: " . scalar(@apps_with_time) . " applications");
            }
        }
    }
    
    ::rptMsg("");
}



sub convertFiletime {
    my $filetime = shift;
    
    return "Invalid timestamp" unless defined $filetime;
    return "Invalid timestamp" if length($filetime) == 0;
    
    my $ft_value;
    
    if (length($filetime) == 8) {
        my ($low, $high) = unpack("LL", $filetime);
        
        eval {
            require Math::BigInt;
            my $big_low = Math::BigInt->new($low);
            my $big_high = Math::BigInt->new($high);
            $ft_value = $big_high->blsft(32)->badd($big_low)->bstr();
        };
        
        if ($@) {
            $ft_value = ($high * 4294967296) + $low;
        }
    } elsif (length($filetime) == 4) {
        $ft_value = unpack("L", $filetime);
    } else {
        $ft_value = $filetime;
    }
    
    return "Invalid timestamp" if $ft_value == 0;
    
    my $epoch_diff = 11644473600;
    my $unix_timestamp = ($ft_value / 10000000) - $epoch_diff;
    
    if ($unix_timestamp < 0) {
        return "Pre-1970 timestamp (raw: $ft_value)";
    }
    
    my ($sec, $min, $hour, $mday, $mon, $year) = gmtime($unix_timestamp);
    
    return sprintf("%04d-%02d-%02d %02d:%02d:%02d UTC", 
                   $year + 1900, $mon + 1, $mday, $hour, $min, $sec);
}

sub getFiletimeRaw {
    my $filetime = shift;
    
    return 0 unless defined $filetime;
    return 0 if length($filetime) == 0;
    
    if (length($filetime) == 8) {
        my ($low, $high) = unpack("LL", $filetime);
        return ($high * 4294967296) + $low;
    } elsif (length($filetime) == 4) {
        return unpack("L", $filetime);
    } else {
        return $filetime;
    }
}

1;
