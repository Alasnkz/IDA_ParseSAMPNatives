import idaapi
import idautils
import idc
import os
import glob

natives = []

SAMPIncludes = [
	"a_samp.inc",
	"a_players.inc",
	"a_vehicles.inc",
	"a_actor.inc",
	"a_http.inc",
	"a_npc.inc",
	"a_sampdb.inc",
	"a_objects.inc"
]

# Only SA-MP natives are to be used and supported.
def ImportNativeArgumentsToIDA(filepath):
	global ArgumentsReplacement
	
	os.chdir(filepath)
	for include_name in glob.glob("*.inc"):
		is_valid = False
		
		for i in range(len(SAMPIncludes)):
			if(include_name == SAMPIncludes[i]):
				is_valid = True
		
		if(is_valid):
			include_handle = open(include_name, "r")
			
			for line in include_handle:
				if(line.find("native") != -1): # Its a native.
					native_name = line[:line.find("(")].split(" ")[1]
					native_name = native_name[native_name.find(":")+1:] # Hack to remove stuff like Float:
					natives.append(native_name)
					# Define structure
					
					# VERY hacky. I'm rusty on python...
					arguments = line[line.find("("):].replace("(", "").replace(")", ",)").replace("&", "").replace("[]", "").replace("const", "").split(",")
					arguments = arguments[:len(arguments)-1] # Hack to remove ); \n ending.
					
					struct_id = idc.GetStrucIdByName("Native" + native_name + "Params")
					if struct_id == idc.BADADDR: #No point in going through arguments if struct already exists.
						struct_id = idc.AddStrucEx(-1, "Native" + native_name + "Params", 0)
						idc.Til2Idb(-1, "Native" + native_name + "Params")
						idc.AddStrucMember(struct_id, "param_count", -1, idc.FF_DWRD, -1, 4)
						
						print("Created IDA Struct Native" + native_name + "Params!")
						
						for argument in arguments:
							if(argument.find(":") != -1):
								argument = argument[argument.find(":")+1:] # Another "hack" to remove stuff such as Float:
							
							if(argument.find("=") != -1):
								argument = argument[:argument.find("=")] # Yet again, another "hack" to remove default values in natives.
								
							# Add structure arg
							idc.AddStrucMember(struct_id, argument.replace(" ", ""), -1, idc.FF_DWRD, -1, 4)
					else:
						print("Did not create native structure for native " + native_name + " it already exists in your IDB.")
	
# VERY DIRTY FUNCTION.
# IDA DIDN'T WORK WITH ARRAYS FOR ME (BAD DOCUMENTATION FOR THE MOST PART), FOR SOME REASON SO I HAD TO RESORT TO THIS SLOW MESS.
def ParseAMXNativeInfo():
	ida_string = idautils.Strings()

	last_native = ""
	for string in ida_string:
		for native in natives:
			if(str(string) == native and last_native != native):
				last_native = native
				for xref in XrefsTo(string.ea):
					offset = xref.frm + 4
					for native_addr in XrefsFrom(offset):
						# Rename native handler function n_NativeName
						idc.MakeNameEx(native_addr.to, "n_" + native, idc.SN_NOWARN) 
						
						# Setup function prototype & automate setting the native's 
						tinfo = idaapi.tinfo_t()
						ida_typeinf.guess_tinfo(native_addr.to, tinfo)                     
						funcdata = idaapi.func_type_data_t()
						tinfo.get_func_details(funcdata)
						tinfo2 = idaapi.tinfo_t()
						tinfo2.get_named_type(idaapi.get_idati(), "Native" + native + "Params")
						tinfo3 = idaapi.tinfo_t()
						tinfo3.create_ptr(tinfo2)
						if(len(funcdata)): # For some reason this is 0 for some natives with params? Not sure why...
							funcdata[len(funcdata) - 1].type = tinfo3
							function_tinfo = idaapi.tinfo_t()
							function_tinfo.create_func(funcdata)
							idaapi.apply_tinfo2(native_addr.to, function_tinfo, idaapi.TINFO_DEFINITE)
						

ImportNativeArgumentsToIDA("LINK INCLUDE FOLDER HERE")
ParseAMXNativeInfo()