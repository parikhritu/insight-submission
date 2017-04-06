Hi! 

Thank you for the opportunity to participate in this challange - it was fun! I am (relatively) new to python but it's one of the faster languages I've worked with, so I've coded this project in python. 

I've added 2 additional features to the submission:

### Additional Feature 1 - Mutually exclusive high traffic periods
This feature identities mutually exclusive periods that have the highest volume - for example, if July 17th 10:30:00 is the beginning of high value period, values from Jul 17 10:30:00 - 11:29:59 will not be considered for any other period. This information can be useful to identify any surges on the fanpage (and work to identify their causes).

### Additional Feature 2 - Mutually exlcusive popular daily hours
This feature identifies which mutually exclusive 60 min chunks see the most volume on any given day. This data can be useful to identify peak times on the fanpage, for example 03:30:45 - 04:30:44, and to adjust ad costs accordingly.

The code is commented in detail. The following libraries are used:
	<br />
    pandas <br />
    numpy <br />
    datetime <br />
    time <br />

Thanks!
Ritu Parikh



*** I made a last minute change to the code yesterday (adding exception catching instead of encoding the data on import). Reverting back to the orginial encoding to ensure there are no missed instances. ****