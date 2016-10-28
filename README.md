<h1>Simple Sentience rewrite</h1>
<h2>Protocol detector</h2>
<h3>Steps</h3>
<h4>Capture some traffic</h4>
<p>Capture some traffic as PCAP files.</p>
<h4>Extract streams from pcap files</h4>
<p>Get the full message sent and the packets used to send it from PCAP (packet capture files).</p>
<h4>Generate various statistics of stream</h4>
<p>E.g. </p>
<ul>
<li>Chi squared (randomness of the data)</li>
<li>Average packet size</li>
<li>Packet size standard distribution</li>
<li>Inter-packet arrival time</li>
<li>Port</li>
</ul>
<h4>Detect protocol around dynamic elements</h4>
<h5>Detect dynamic elements in streams</h5>
<ul>
<li>Email addresses</li>
<li>User IDs</li>
<li>Names</li>
<li>Usernames</li>
</ul>
<h5>Use characters either side of dynamic elements to take steps in dimensions</h5>
<p>Take rolling 4 character window over 50 characters before and after the dynamic elements. Each 4 character (byte) block is a step in that dimension…</p>
<h4>Store streams in N-space</h4>
<h4>Cluster and plot streams</h4>
<p>All pretty like.</p>
