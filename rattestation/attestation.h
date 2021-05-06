#ifndef IP_AGENT_ATTESTATION_H
#define IP_AGENT_ATTESTATION_H
/*
 * Do the attestation request
 *
 * This function generates the attestation request and sends a protobuf
 * attestation request to the remote host. It further registers a
 * callback to process the response and does the validation.
 * the validation result is provided back to the caller by the
 * provided resp_verivied_cb function.
 */
int
attestation_do_request(const char *host, char *config_file, void (*resp_verified_cb)(bool));
#endif /* IP_AGENT_ATTESTATION_H */
