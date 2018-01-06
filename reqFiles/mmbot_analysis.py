#!/usr/bin/python

import sys
from mmbot import MaliciousMacroBot

mmb = MaliciousMacroBot()
mmb.mmb_init_model()

result = mmb.mmb_predict(sys.argv[1], datatype='filepath')

print result.iloc[0]
