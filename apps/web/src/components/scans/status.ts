/**
 * The states in which a scan is still doing something.
 *
 * The one list: the scans page polls while any scan is in one of these, the
 * card offers Watch rather than Open, the header's indicator and the dashboard
 * show a scan under way, and the wizard chooses between its Scan and Result
 * steps. Its own module because a constant exported beside a component defeats
 * fast refresh for that file.
 */
export const IN_FLIGHT = ["QUEUED", "DISCOVERING", "NORMALIZING", "EVALUATING", "CALCULATING_RISK"];
