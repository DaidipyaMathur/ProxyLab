#ifndef INTRUDER_HPP
#define INTRUDER_HPP

/**
 * @brief Runs the intruder feature.
 *
 * This function prompts the user for a request template file, a payload file,
 * and an output directory. It then iterates through the payloads, injects them
 * into the request, sends the request to the target server, and saves the
 * response to a file.
 */
void run_intruder();

#endif // INTRUDER_HPP
