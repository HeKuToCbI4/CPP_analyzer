#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from tkinter import *

class FORM(object):

	def __init__(self, title: str, geometry: str, font: (str, int)):
		self.root = Tk()
		self.root.update()
		self.root.title(title)
		self.root.geometry(geometry)
		self.root.resizable(width=True, height=True)
		self.root.minsize(self.root.winfo_width(), self.root.winfo_height())
		self.root.protocol('WM_DELETE_WINDOW', self.Exit)
		self.font = font

	#def CreateButton(self, parent: Tk, width: int, height: int, text: str, action=None):
	#	button = Button(parent, text=text, font=self.font, width=width, height=height, relief=RAISED)
	#	button.bind('<Button-1>', action)
	#	return button

	def CreateCheckbutton(self, parent: Tk, text: str, height: int, width: int, anchor, value: int=1):
		value = IntVar(value=value)
		CHButton = Checkbutton(parent, variable=value, text=text, height=height, width=width, anchor=anchor)
		CHButton.pack()
		return value, CHButton

	def CreateListbox(self, parent: Tk, selectmode, borderwidth: int, action=None):
		listbox = Listbox(parent, selectmode=selectmode, exportselection=False, borderwidth=borderwidth)
		listbox.pack(fill=BOTH, expand=TRUE)
		listbox.bind('<<ListboxSelect>>', action)
		return listbox

	def FillListbox(self, listbox: Tk, items: tuple or list):
		for item in items:
			listbox.insert(END, item)

	def WriteToText(self, Textfield: Tk, text: str or list or tuple, option: str=NONE):
		Textfield.configure(state=NORMAL)
		if option=='CLEAR':Textfield.delete('1.0', END)
		if isinstance(text, (list, tuple)):
			for line in text: Textfield.insert(END, str(line)+'\n')
		else: Textfield.insert(END, text)
		Textfield.configure(state=DISABLED)

	def CreateScrollbox(self, frame: Tk, item: Tk, orient=HORIZONTAL):
		scrollbar = Scrollbar(frame, orient=orient)
		scrollbar.config(command=item.xview if orient==HORIZONTAL else item.yview)
		scrollbar.pack(side=BOTTOM if orient==HORIZONTAL else RIGHT, fill=X if orient==HORIZONTAL else Y)
		item.config(xscrollcommand=scrollbar.set if orient==HORIZONTAL else NONE, yscrollcommand=scrollbar.set if orient==VERTICAL else NONE)
		item.pack(expand=YES, side=TOP if orient==HORIZONTAL else LEFT, fill=BOTH)
		return scrollbar

	def Error(self, message: str):
		from tkinter import messagebox
		self.root.withdraw()
		messagebox.showerror("Error", message)

	def Start(self):
		try:
			self.root.mainloop()
		except Exception as e:
			self.Error(e.args)

	def Exit(self, event=None):
		try:
			self.root.destroy()
		except Exception as e:
			self.Error(e.args)


FONT = ('Hermit', 8)
#TEXT_WIDTH	= 100
#TEXT_HEIGHT	= 400
BUTTON_WIDTH	= 20
BUTTON_HEIGHT	= 1


class UI(object):

	def __init__(self, VULNERABILITIES):
		self.Programms, self.Tests = self.GetRequired()
		self.vulnerabilities = VULNERABILITIES

	def GetRequired(self):
		from tkinter.filedialog import askopenfilenames
		from os import getcwd, listdir
		#from os.path import basename

		try:
			root = Tk()
			root.withdraw()
			Programms = [ P for P in list(askopenfilenames(title='Import Program(s) to Analyze', initialdir=getcwd(), filetypes=[("CPP",".cpp")])) ]	# '.*' -> '.cpp'
			Tests = [ getcwd()+'/tests/'+file for file in listdir(getcwd()+'/tests') if file.endswith(".cpp") ]	# .cc .c
		except IOError as e:
			from tkinter import messagebox
			messagebox.showwarning("Warning", "Folder 'tests' doesn't exist")
			Tests = []
		except Exception as e:
			from tkinter import messagebox
			messagebox.showwarning("Warning", e.args)
		finally:
			root.destroy()

		return Programms, Tests

	def StartMain(self, HANDLER):
		from os.path import basename
		from os import getcwd
		def ProgramsToAnalyze(root, listbox: Tk):
			from tkinter import _tkinter
			try:
				#return [listbox.get(listbox.curselection())]						# SINGLE SELECTION
				programs = [ listbox.get(idx) for idx in listbox.curselection() ]	# EXTENDED SELECTION
				if not len(programs):
					raise _tkinter.TclError
				return programs
			except _tkinter.TclError:
				from tkinter import messagebox
				messagebox.showwarning("Warning", "No Program Selected")
				return ()

		def VulnerabilitiesToFind(root, CheckbuttonsArray: tuple or list):
			from tkinter import _tkinter
			try:
				vulnerabilities = [item[1].cget('text') for item in CheckbuttonsArray if item[0].get()]
				if not len(vulnerabilities):
					raise _tkinter.TclError
				return vulnerabilities
			except _tkinter.TclError:
				from tkinter import messagebox
				messagebox.showwarning("Warning", "No Vulnerability Selected")
				return ()

		try:
			Mainform = FORM('Static Code Analyzer', '650x450', FONT)
			Mainform.root.focus_force()

			frame1 = Frame(Mainform.root, borderwidth=0, relief="groove", width=100, height=400)
			frame2 = Frame(Mainform.root, borderwidth=2, relief="groove", width=100, height=400)
			frame3 = Frame(Mainform.root, borderwidth=2, relief="groove", width=200, height=400)
			'''V1 = Mainform.CreateCheckbutton(frame1, text = "Buffer Overflow",					 height=1, width=25, anchor=W)
			V2 = Mainform.CreateCheckbutton(frame1, text = "Format String Vulnerability",		 height=1, width=25, anchor=W)
			V3 = Mainform.CreateCheckbutton(frame1, text = "SQL injection",					 height=1, width=25, anchor=W)
			V4 = Mainform.CreateCheckbutton(frame1, text = "Command Injection",				 height=1, width=25, anchor=W)
			V5 = Mainform.CreateCheckbutton(frame1, text = "Neglect of Error Handling",		 height=1, width=25, anchor=W)
			V6 = Mainform.CreateCheckbutton(frame1, text = "Bad Data Storage Management",		 height=1, width=25, anchor=W)
			V7 = Mainform.CreateCheckbutton(frame1, text = "Data Leak",						 height=1, width=25, anchor=W)
			V8 = Mainform.CreateCheckbutton(frame1, text = "Not Crypto-resistant Algorithms",	 height=1, width=25, anchor=W)
			V9 = Mainform.CreateCheckbutton(frame1, text = "Integer Overflow",				 height=1, width=25, anchor=W)
			V10 = Mainform.CreateCheckbutton(frame1, text = "Race Condition",					 height=1, width=25, anchor=W)
			V11 = Mainform.CreateCheckbutton(frame1, text = "Readers–writers problem",		 height=1, width=25, anchor=W)'''
			V = tuple([ Mainform.CreateCheckbutton(frame1, text = vulnerability, height=1, width=25, anchor=W) for vulnerability in self.vulnerabilities ])
			lb2 = Mainform.CreateListbox(frame2, EXTENDED, 0)
			lb3 = Mainform.CreateListbox(frame3, EXTENDED, 0)
			Mainform.FillListbox(lb2, [ basename(file) for file in self.Tests ])
			Mainform.FillListbox(lb3, self.Programms)
			Mainform.CreateScrollbox(frame3, lb3)

			button1 = Button(Mainform.root, width=BUTTON_WIDTH, height=BUTTON_HEIGHT, state=NORMAL if self.Tests else DISABLED, font=Mainform.font, text="Analyze N Tests",
			                command=lambda: self.FindVulnerabilities( [ getcwd()+'/tests/'+file for file in ProgramsToAnalyze(Mainform.root, lb2) ], VulnerabilitiesToFind(Mainform.root, V), HANDLER ))
			button2 = Button(Mainform.root, width=BUTTON_WIDTH, height=BUTTON_HEIGHT, state=NORMAL if self.Tests else DISABLED, font=Mainform.font, text="Analyze All Tests",
			                command=lambda: self.FindVulnerabilities( self.Tests, VulnerabilitiesToFind(Mainform.root, V), HANDLER ))
			button3 = Button(Mainform.root, width=BUTTON_WIDTH, height=BUTTON_HEIGHT, state=NORMAL if self.Programms else DISABLED, font=Mainform.font, text="Analyze N Programs",
			                command=lambda: self.FindVulnerabilities( ProgramsToAnalyze(Mainform.root, lb3), VulnerabilitiesToFind(Mainform.root, V), HANDLER ))
			button4 = Button(Mainform.root, width=BUTTON_WIDTH, height=BUTTON_HEIGHT, state=NORMAL if self.Programms else DISABLED, font=Mainform.font, text="Analyze All Programs",
			                 command=lambda: self.FindVulnerabilities( self.Programms, VulnerabilitiesToFind(Mainform.root, V), HANDLER ))

			frame1.grid(column=0, row=0,	padx=(12,8),	pady=(5,10), sticky=(N, S, E, W))
			frame2.grid(column=1, row=0,	padx=(8,8),	pady=(5,10), sticky=(N, S, E, W))
			frame3.grid(column=2, row=0,	padx=(8,12),	pady=(5,10), columnspan=2, sticky=(N, S, E, W))
			button1.grid(column=0, row=1, padx=(12,8),	pady=(0,12))
			button2.grid(column=1, row=1, padx=(8,8),	pady=(0,12))
			button3.grid(column=2, row=1, padx=(8,8),	pady=(0,12))
			button4.grid(column=3, row=1, padx=(8,12),	pady=(0,12))

			Mainform.root.columnconfigure(0, weight=0)
			Mainform.root.columnconfigure(1, weight=1)
			Mainform.root.columnconfigure(2, weight=10)
			Mainform.root.columnconfigure(3, weight=10)
			Mainform.root.rowconfigure(0, weight=1)
			Mainform.root.rowconfigure(1, weight=0)

			Mainform.Start()
		except Exception as e:
			from tkinter import messagebox
			Mainform.Error(e.args)
			Mainform.Exit()

	def FindVulnerabilities(self, programs: tuple or list, vulnerabilities: tuple or list, HANDLER):
		if not (programs and vulnerabilities): return 0
		from Threading import create_workers, create_jobs
		from queue import Queue, Empty
		try:
			queue = Queue()
			create_workers(len(programs), self.StartVulnerabilities, queue)
			#content = lambda program: dict([ (vulnerability, 'Here will be Code for "{}"'.format(vulnerability)) for vulnerability in vulnerabilities ])
			content = lambda program: dict([ (vulnerability, HANDLER(vulnerability, program)) for vulnerability in vulnerabilities if HANDLER(vulnerability, program) ])
			create_jobs([ (program, content(program)) for program in programs if content(program) ], queue)
		except Empty:
			from tkinter import messagebox
			messagebox.showinfo("Info", "No vulnerabilities detected")

	def StartVulnerabilities(self, queue):
		try:
			program, content = queue.get(block=True)
			queue.task_done()
			Vulnerabilitiesform = FORM(program+' Vulnerabilities', '600x250', FONT)

			l1 = Label(Vulnerabilitiesform.root, text='Vulnerabilities found:', font=Vulnerabilitiesform.font, width=28, anchor='w')
			l2 = Label(Vulnerabilitiesform.root, text='Where:', font=Vulnerabilitiesform.font, anchor='w')

			found = Frame(Vulnerabilitiesform.root, borderwidth=2, relief="groove", width=28, height=20)
			where = Frame(Vulnerabilitiesform.root, borderwidth=2, relief="groove", width=150, height=20)
			foundlb = Vulnerabilitiesform.CreateListbox(found, SINGLE, 0, action=lambda event: Vulnerabilitiesform.WriteToText(wheretb, content[foundlb.get(foundlb.curselection())], 'CLEAR'))
			wheretb  = Text(where, borderwidth=0, relief="groove", wrap=WORD, state='disabled')
			Vulnerabilitiesform.CreateScrollbox(where, wheretb, VERTICAL)
			Vulnerabilitiesform.FillListbox(foundlb, content.keys())

			l1.grid(column=0, row=0,	  padx=(12,8), pady=(5,2),  sticky=(N, S, E, W))
			l2.grid(column=1, row=0,	  padx=(8,8),  pady=(5,2),  sticky=(N, S, E, W))
			found.grid(column=0, row=1, padx=(12,8), pady=(0,10), sticky=(N, S, E, W))
			where.grid(column=1, row=1, padx=(8,12), pady=(0,10), sticky=(N, S, E, W))

			Vulnerabilitiesform.root.columnconfigure(0, weight=1)
			Vulnerabilitiesform.root.columnconfigure(1, weight=20)
			Vulnerabilitiesform.root.rowconfigure(0, weight=0)
			Vulnerabilitiesform.root.rowconfigure(1, weight=1)

			Vulnerabilitiesform.Start()
		except Exception as e:
			from tkinter import messagebox
			Vulnerabilitiesform.Error(e.args)
			Vulnerabilitiesform.Exit()
