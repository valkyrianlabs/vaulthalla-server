## Acknowledge and silence findings in the web console

The Health Overview's "Needs attention" list now shows what has been said about each finding: not acknowledged,
acknowledged by whom and when, or silenced by whom and until when, with the note if one was left. Accounts that may
manage findings (`admin.stats.manage`) get **Acknowledge**, **Silence** (1 hour, 24 hours, 7 days or until turned
back on, with an optional note of up to 500 characters) and a link to the page that helps, next to each finding.
A new **Silenced** list shows every silence, including those whose finding is not active now, with **Turn back on**.

The health dot in the top bar now counts only what nobody has acknowledged or silenced, and says "Nothing new" when
everything has been seen. The Health pages keep the true status and counts: a silenced error is still an error there.

The console now follows health changes by push instead of polling the health status, so the dot and the lists update
within seconds of a change or of another operator acknowledging or silencing a finding.
