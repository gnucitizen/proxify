#!/usr/bin/env python

# ---

import sys

# ---

sys.stderr.write('>>> echo started\n');

# ---

class _GetchWindows:
	def __init__(self):
		import msvcrt
		
	def __call__(self):
		import msvcrt
		
		return msvcrt.getch()
		
#
class _GetchMacCarbon:
	def __init__(self):
		import Carbon
		
		Carbon.Evt
		
	def __call__(self):
		import Carbon
		
		if Carbon.Evt.EventAvail(0x0008)[0]==0:
			return ''
		else:
			(what, msg, when, where, mod) = Carbon.Evt.GetNextEvent(0x0008)[1]
			
			return chr(msg & 0x000000FF)
			
class _GetchUnix:
	def __init__(self):
		import tty, sys
		
	def __call__(self):
		import sys, tty, termios
		
		fd = sys.stdin.fileno()
		
		try:
			old_settings = termios.tcgetattr(fd)
			it_works = True
		except:
			old_settings = None
			it_works = False
			
		try:
			try:
				tty.setraw(sys.stdin.fileno())
			except:
				pass
				
			ch = sys.stdin.read(1)
		finally:
			if it_works:
				termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
				
		return ch
		
class _Getch:
	"""Gets a single character from standard input. Does not echo to the screen."""
	
	def __init__(self):
		try:
			self.impl = _GetchWindows()
		except ImportError:
			try:
				self.impl = _GetchMacCarbon()
			except(AttributeError, ImportError):
				self.impl = _GetchUnix()
				
	def __call__(self):
		return self.impl()
		
# ---

getch = _Getch()

while True:
	c = getch()
	
	sys.stderr.write(c)
	sys.stdout.write(c)