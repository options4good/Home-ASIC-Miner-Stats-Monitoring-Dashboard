<h1>Home ASIC Miner Stats Monitoring Dashboard</h1>
Home ASIC Miner Stats Monitoring Dashboard Application for: Bitaxe, NerdQaxe, Lucky Miner, Avalon Q, Avalon Nano &amp; More. A perfect way to view stats for all of your home miners in one place. I hope I can contribute with this small project to the community and many of you will enjoy my creation. The dashboard application supports and can receive and display data from Bitaxe, NerdQaxe, Lucky Miner and Avalon home miners.<br><br>

<img width="848" height="483" alt="minerdashboardv248" src="https://github.com/user-attachments/assets/7907f81c-a262-4da4-add0-46650ff3fe7e" />

<h2>What are the current features?</h2>

<h3>Global Status section:</h3>
<b>Total =</b> the total hashrate combined of all currently added and running miners.<br>
<b>Online =</b> how many miners are present out of all that were added in the configuration.<br>
<b>Date and Time Stamp =</b> to display the current date and time.<br>
<b>Version =</b> the version number of the application currently installed.<br><br>

<h3>Performance section:</h3>
<b>Miner =</b> the list of available miners added in the configuration plus 'workmode' indicator for Avalon miners.<br>
<b>Hashrate =</b> displays the current hashrate the miner is hashing.<br>
<b>Efficiency =</b> the efficiency value of the miner. The formula is: hashrate/DC wattage = efficiency (J/Th or W/Th).<br>
<b>Temp Asic/VR =</b> the temperature of the ASIC chips and the Voltage regulator.<br>
<b>Power Volt/DC/AC =</b> Input power from PSU in voltage, DC power the unit uses in wattage and AC power (at wall outlet).<br>
<b>Asic Volt/Freq =</b> the millivoltage value of each Asic chip and what frequency it is operating on<br>
<b>Fan =</b> the percentage of speed the cooling fan is running at and the RPM value. (Avalon products do not provide exact RPM value, only percentage).<br><br>

<h3>Mining section</h3>
<b>Miner =</b> the list of available miners added in the configuration.<br>
<b>Uptime =</b> the time elapsed since the miner has been monitored by the dashboard application.<br>
<b>Best Diff All-time =</b> the highest difficulty that the miner has ever achieved. (Avalon products do not provide this value).<br>
<b>Best Diff Session =</b> the highest difficulty that the miner achieved since it was last powered on.<br>
<b>Accepted/Rejected =</b> the number of submitted shares that were accepted and rejected by the pool the miner is mining to.<br>
<b>Pool Diff =</b> the difficulty level the miner is submitting shares to the pool. (Avalon, Bitaxe and Lucky Miner products do not provide this number).<br>
<b>Blocks =</b> the number of blocks the miner has found.<br><br>

<h3>Connectivity section</h3>
<b>Miner =</b> the list of available miners added in the configuration.<br>
<b>IP Address =</b> displaying the Ip Address of the miner that was added to configuration.<br>
<b>Pool URL =</b> the location where the miner is pointed to.<br>
<b>Ping =</b> the latency between the miner and the location that is pointed to.<br>
<b>Username/Worker =</b> the username the miner is set up in the miner's setting and the worker name if it was set up in the miner's setting.<br><br>

<h3>Activity section</h3>
<b>Activity =</b> displays the activity of the submitted shares or block found of each miner in real time.<br><br>

<h2>What are the upcoming features?</h2>
I am open to feedback and future requests to enhance the capability of this application. Please do not hesitate to write up an issue if you notice anything not working properly. Alternatively, you can reach out via Reddit: https://www.reddit.com/r/Options4Good/<br><br>

<h2>Installation, Configuration & Start</h2>
<b>Linux Dependencies</b><br><br>
In the terminal perform the below command:<br><br>

```bash
sudo apt update && sudo apt install python3 python3-pip python3-venv -y
```

Download the latest minerdashboard.py file from the "Releases" section: https://github.com/options4good/Home-ASIC-Miner-Stats-Monitoring-Dashboard/releases<br><br>

<b>Configuration</b><br><br>
Open the file in a text editor (or do nano minerdashboard.py in terminal)<br><br>
Locate the "# --- Configuration ---" section<br><br>
You will find a series of pre-configured miners as for an example. They should look similar like these lines:<br><br>
    {"ip": "10.0.0.3", "name": "Avalon-Q-01", "type_hint": "avalon"},<br>
    {"ip": "10.0.0.23", "name": "Avalon-Nano3S-01", "type_hint": "avalon"},<br>
    {"ip": "10.0.0.47", "name": "Lucky-LV07-01", "type_hint": "lucky"},<br>
    {"ip": "10.0.0.53", "name": "Nerd-02", "type_hint": "nerd"},<br>
    {"ip": "10.0.0.130", "name": "Nerd-01", "type_hint": "nerd"},<br>
    {"ip": "10.0.0.147", "name": "Gamma-01", "type_hint": "nerd"}<br><br>
Alter the lines as you need. Replace the IP address with your miners' IP address. (Leave quotation marks)! Replace the value in the "name" to whatever your miner's name is. CAUTION! DO NOT ALTER THE VALUE IN THE "type_hint"!!! That value must stay, otherwise the application will not function properly! Any Avalon products, use "avalon". Any Bitaxe and NerdQaxe products use "nerd". Any Lucky Miner products use "lucky".<br>
NOTE: the last configuration line DOES NOT HAVE the comma "," at the end! IF you will configure only one miner make sure that the comma is not present at the end. A comma is only required if you are adding multiple lines; do not include a comma on the final line!!!<br><br>
Save the file.<br><br>
Start the application from the terminal running the below command:

```bash
python3 minerdashboard.py
```

<br>

<h4>Donations are highly appreciated and can be made via crypto:</h4>
<b>DGB</b> wallet address:&nbsp;&nbsp;DEkZrJo1BHdiqnQq1XQSWGymEcDWGAWwZs<br>
<b>DOGE</b> wallet address:&nbsp;&nbsp;DKZ9sv4VoTiQQdwi7VY25573UfpQqZJfYf<br>
<b>LTC</b> wallet address:&nbsp;&nbsp;MJw3XHpR65Ec8rKEBthK5Dnvcy1CixYGTa<br>
<b>BCH</b> wallet address:&nbsp;&nbsp;bitcoincash:qq66dg3vhczrqf4zy4kxje3c45vz47khsufsludxcc<br><br>
Thank you.
<br><br>
