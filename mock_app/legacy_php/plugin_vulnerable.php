<?php
/**
 * Plugin Name: Vulnerable User Profiles
 * Description: A mock vulnerable WordPress plugin for testing Ensemble AI patching capabilities.
 * Version: 1.0.0
 */

// Register AJAX handler for unauthenticated users
add_action('wp_ajax_nopriv_update_profile_data', 'vuln_update_profile_data');

function vuln_update_profile_data() {
    // ASSUMPTION VIOLATED: The developer assumed only base64 profile data from the frontend
    // would be submitted and that base64 encoding prevents payload execution.
    // Also, no nonce verification and no permission checks are present.
    
    if (isset($_POST['profile_data'])) {
        $encoded_data = $_POST['profile_data'];
        $decoded_data = base64_decode($encoded_data);
        
        // SINK: Unsafe deserialization of user-controlled input
        // Reaching this sink can lead to PHP Object Injection / Remote Code Execution (RCE)
        $profile = unserialize($decoded_data);
        
        // Save profile option
        update_option('user_profile_settings', $profile);
        
        wp_send_json_success(array('message' => 'Profile updated successfully.'));
    } else {
        wp_send_json_error(array('message' => 'Missing profile_data.'));
    }
}
