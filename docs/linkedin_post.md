A 3-second yellow light is legal to a traffic signal controller. On a 45-mph road it is a second too short, and it doesn't change delay at all.

Most signal controllers are managed over NTCIP on SNMPv1, where the "password" travels in clear text. So I built a guard that sits in the cabinet between the central system and the controller, and checks every command against the intersection's geometry and timing standards before it gets through.

I tested it with 155 one-hour simulations of an actuated-coordinated intersection. The attacker spoofs the central system and knows the password:
- No guard: holding the main street green pushed delay from 41 to 381 s/veh. The short-yellow attack left delay unchanged but served 48 unsafe yellows.
- With the guard: every direct attack blocked, delay unchanged, zero false alarms in 20 normal hours.

Two lessons:
1. Defence in depth isn't a slogan. Command rules alone missed a rapid-cycling attack (delay 256 s/veh), because the first command got through before the rate limit tripped. A monitor watching what the signal actually displayed caught it and restored the plan.
2. Flash is the safe fallback, but it costs 15-33 minutes of all-way stop. Stopping bad commands early beats recovering from them.

What nothing caught: replaying a valid, captured command at the wrong time. That needs authenticated, time-stamped messages (SNMPv3), not a smarter filter.

Repo: https://github.com/faysalchowdhoury/ntcip-signal-tamper-guard

Signal engineers: how many of your field controllers still run SNMPv1 with default communities?

#TrafficSignals #NTCIP #Cybersecurity #ITS #TransportationEngineering #CriticalInfrastructure #Python
