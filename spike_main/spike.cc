#include "handcar_cosim_wrapper.h"
#include "sim.h"
#include "mmu.h"
#include "cachesim.h"
#include "extension.h"
#include <dlfcn.h>
#include <fesvr/option_parser.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <numeric>
#include <fstream>
#include <iostream>
#include <ios>
#include <iomanip>

#include <cstring> 

//For fooling input arguments
#include <string.h>

//controls
#define ARGV_ELEMENT_BUFFER_SIZE 128 // The number of characters in --<option_name>=<argment> for a particular option
#define NOISY true

//To manage the lifecycle of the simulator objects for library use, and to keep stack memory use to a minimum. pointers are manually managed.
simlib_t* _pSimulatorTopLevel = nullptr;
icache_sim_t* ic = nullptr;
dcache_sim_t* dc = nullptr;
cache_sim_t* l2 = nullptr;
//std::function<extension_t*()> extension;

//Persistent options class and support, designed to keep consistency with Spike's existing options
//Options storage manages the setting and retrieval of options stored as OptionsPrimitives
class OptionsStorage
{
  //OptionsPrimitive is a record type used to store the definition of an option as well as its settings either default or after user modification.
  struct OptionsPrimitive
  {
    bool mIsUsed;
    char mShortName;
    std::string mLongName;
    bool mNeedsVal;
    bool mNeedsPath;
    uint64_t mVal;
    std::string mPath;
  };

  enum DESCRIPTIVE_INITIALIZATION_VALUES : bool
  {
    NEEDS_VAL = true,
    NEEDS_PATH = true,
    USED = true,
    UNUSED = false
  };

  enum ERROR_CODES : int
  {
    SUCCESS = 0,
    NAME_NOT_FOUND = 1,
    VAL_IS_NULL = 2,
    PATH_IS_NULL = 3,
    NAME_IS_NULL = 4,
    ARGV_MEMORY_ERROR = 5
  };

  std::string _flat_options; // temporary storage of a space separated options string following the format of a command line argument given to Spike original executable.
  char** _stored_argv; // options reformatted into an argument vector suitable for input to Spike's original input parsing code.
  int _stored_argc; // number of elements in the argument vector _stored_argv.
  std::map<std::string, OptionsPrimitive> _options_map; // used to support calls to set_simulator_parameter, used to encode option vocabulary, argument requirements and which options are enabled.  
  std::vector<std::string> _token_vector; // buffer to store parsed argument vector elements, used to support when initialize_simulator is called with a non-null char* input and set_simulator_parameter is not used.
  
  // _allocateDummyOptions function: the class has a few execution pathways, all of which require that the setting of the first and last elements of _stored_argv to some dummy values
  //
  // inputs:
  //    _stored_argc (implicit), needs to be up to date with regards to number of elements in _stored_argv
  //    _stored_argc (implicit), needs at least two element slots 
  //
  // outputs:
  //    _stored_argv (implicit), allocates and sets the values of the first and last elements of _stored_argv
  void _allocateDummyOptions()
  {
    // Allocate the elements of argv starting first with with first and last, which are dummy arguments.
    _stored_argv[0] = (char*)malloc(20 * sizeof(char));
    _stored_argv[_stored_argc-1] = (char*)malloc(20 * sizeof(char));
    const char arg1[] = "handcar_cosim\0";
    const char arg2[] = "no_elf\0";
    memcpy(_stored_argv[0], arg1, strlen(arg1)+1);
    memcpy(_stored_argv[_stored_argc-1], arg2, strlen(arg2)+1);
  }

  
  // _unpackFlatOptions function: takes a space separated options string, formatted as it would be for command line arguments for the Spike original executable, 
  //    and recomposes it into an argument vector so that spike argument parsing code can work exactly as it was designed to work. 
  //    This is needed because Verilog does not have a char** equivalent type and the philosphopy of this adaptation is to change as little of Spike as necessary.
  //
  // inputs:
  //   _flat_options (implicit)
  //
  // outputs:
  //   _token_vector (implicit)
  //
  void _unpackFlatOptions()
  {
    if(_flat_options == "")
    {    
      if(NOISY)
      {
        printf("### handcar_cosim::OptionsStorage::_unpackFlatOptions(): No options specified.\n");
      }
      return;
    }

    size_t pos = 0;
    std::string inter_argument_delimeter = " ";
    std::string token;
    std::string flat_options_temp = _flat_options;

    // Using a ' ' as a delimeter, break the options string into tokens and save those tokens into _token_vector
    while((pos = flat_options_temp.find(inter_argument_delimeter)) != std::string::npos)
    {
      token = flat_options_temp.substr(0, pos);
      flat_options_temp = flat_options_temp.substr(pos + inter_argument_delimeter.length());   
      
      // all cases we ultimately leave to the original Spike code to validate
      _token_vector.push_back(token);
    }
    // Handle the case that there is just a single option, or a single option left.
    if(flat_options_temp.size() > 0)
    {
      _token_vector.push_back(flat_options_temp);
    }
  }


  // _rejectOrEnroll function: looks up an option by name from the _options_map and determines if the right types of arguments have been provided. If so, the option is enabled and the argument is stored.
  //
  // inputs:
  //   name, the keyname for the option, follows the name used by Spike originally, must not have '-' or '--' prefixes. 
  //   pValue, if the option takes a numeric argument, this pointer should not be null
  //   path, if the option takes any kind of string argument such as a comma-separated list, the path pointer should not be null
  //
  // outputs:
  //  _options_map (implicit), USED field and arguements fields are updated for enabled options
  //
  // returns:  
  //   returns error codes to indicate the nature of a deficiency or success status
  //   NAME_IS_NULL, VAL_IS_NULL, PATH_IS_NULL and SUCCESS     
  //
  //   _options_map (implicit), if an option is correctly specified the _options_map will be updated
  //
  // note: friendship is used to allow set_simulator_parameter to call this function. 
  //     Options cannot be de-activated once set, but they can be re-specified.
  //
  int _rejectOrEnroll(const char* name, const uint64_t* pValue, const char* path)
  {
    if(name == nullptr)
    {
      if(NOISY)
      {
        printf("### handcar_cosim::OptionsStorage::_rejectOrEnroll, null option name.\n");
      }
      return NAME_IS_NULL;
    }

    //Is this option part of the known vocabulary?
    auto map_item = _options_map.find(name);
    if(map_item == _options_map.end())
    {
      if(NOISY)
      {
         printf("### handcar_cosim::OptionsStorage::_rejectOrEnroll, cannot find option '%s'.\n", name);
      }
      return NAME_NOT_FOUND;
    }

    if(map_item->second.mNeedsVal)
    {
      if(pValue == nullptr)
      {
        if(NOISY)
        {
          printf("### handcar_cosim::OptionsStorage_rejectOrEnroll, numeric value for option %s is needed, but is null.\n", name);
        }
        return VAL_IS_NULL;
      }
      else
      {
        map_item->second.mVal = *pValue;
      }
    }

    if(map_item->second.mNeedsPath)
    {
      if(path == nullptr)
      {
        if(NOISY)
        {
          printf("### handcar_cosim::OptionsStorage_rejectOrEnroll, path / string for option %s is needed, but is null.\n", name);
        }
        return PATH_IS_NULL;
      }
      else
      {
        map_item->second.mPath = path;
      }
    }

    // Set the option as USED in the map only after all the sanity checks have passed.
    map_item->second.mIsUsed = true;

    return  SUCCESS;
  }


  // _resetArgMatrix function: clears the memory allocated to char** _stored_argv, uses count of number of enabled options to resize char** _stored_argv. 
  //               Then, memory is allocated for the elements and the first and last elements are set to dummy arguements.
  //
  // inputs:
  //    _options_map (implicit), scanned to accumulate a count of the number of options that are 'USED'
  //
  // outputs:
  //    _stored_argv (implicit), contains formatted options equivalent to what Spike original main would have seen with the same options reqested
  //    _stored_argc (implicit), indicates the number of elements in _stored_argv
  //
  // returns:
  //    Error codes:
  //    ARGV_MEMORY_ERROR if _stored_argv cannot be allocated
  //    SUCCESS if everything proceeded ok
  //
  // notes:
  //    allocates a fixed amount of memory for each of the argument vector elements, ARGV_ELEMENT_BUFFER_SIZE characters of memory. This might be insufficient for extremely long file-paths. 
  //    128 characters: 11111111222222223333333344444444555555556666666677777777888888881111111122222222333333334444444455555555666666667777777788888888
  //
  //    needs to be called after a group of calls to enrollOrReject, not needed if the const char* constructor was used.
  int _resetArgMatrix()
  {
    // Wipe out the old data in _stored_argv and its elements
    for(int arg_num = 0; arg_num < _stored_argc; ++arg_num)
    {
      free(_stored_argv[arg_num]);
      _stored_argv[arg_num] = nullptr;
    }
    free(_stored_argv);
    _stored_argv = nullptr;    
    _stored_argc = 0;

    // lambda function to for counting number of options to set so that the argv can be resized
    auto add_one_if_used = [](int count, const std::pair<std::string, OptionsPrimitive>& option_record)
    {
      if(option_record.second.mIsUsed)
        return ++count;
      else
        return count; 
    };
    int num_options_used = 2 + std::accumulate(_options_map.begin(), _options_map.end(), int(0), add_one_if_used); 

    // We added two entries for the first and last arguments which are dummies: the host executable name and a placehold for the ELF name. 
    // The ELF file is dealt with by a totally different API function than set_simlator_parameter, so we just set a dummy vlaue here for now.

    // Allocate argv
    _stored_argv = (char **)malloc(num_options_used * sizeof(char*));
    if(_stored_argv == nullptr)
    {
      if(NOISY)
      {
        printf("### handcar_cosim::OptionsStorage::_resetArgMatrix, unable to allocate _stored_argv.\n");
      }
      return ARGV_MEMORY_ERROR;
    }
    else
    {
      _stored_argc = num_options_used;
    }

    // Allocate the elements of argv starting first with with first and last, which are dummy arguments.
    _allocateDummyOptions();

    for(int arg_num = 1; arg_num < (_stored_argc-1); ++arg_num)
    {
      _stored_argv[arg_num] = (char*)malloc(ARGV_ELEMENT_BUFFER_SIZE * sizeof(char));  
    }
      
    return SUCCESS;    
  }


  // _loadArgMatrix function: once memory has been allocated for char** _stored_argv, scan the _options_map for enabled options and write them into the argv. 
  //
  // inputs:
  //    _options_map (implicit), read to determine what to put into the _stored_argv array.
  //
  // outputs:
  //    _stored_argv (implicit), enabled options are re-encoded and written into the memory allocated for them.
  //
  // returns:
  //    Error codes:
  //    ARGV_MEMORY_ERROR if an option token cannot be written into the _stored_argv
  //    SUCCESS if everything proceeded ok
  //
  // Needs to be called after _resetArgMatrix
  int _loadArgMatrix()
  {
    // we start the arg_num at 1 because 0 is reserved for a dummy argument
    int arg_num = 1;
    for(const auto& map_item : _options_map) // we should have called resetArgMatric alread so that we already know know much room we need for the used options in this map.
    {
      if(map_item.second.mIsUsed)
      {
        std::string temp("");

        // Spike options are short only or long only, except for help, which of those is this one?
        if(map_item.second.mShortName == '0')
        {
          temp += ("--");
          temp += map_item.second.mLongName;
          if(map_item.second.mNeedsVal || map_item.second.mNeedsPath)
          {
            temp += "=";      
          }
        }
        else
        {
          temp += "-";
          temp += map_item.first;
        }

        // Spike options sometimes take single scalar numeric values, but most of them take a string, and some of them take no argument; which case is it here?
        if(map_item.second.mNeedsVal)
        {
          temp += std::to_string(map_item.second.mVal);
        }
        else if(map_item.second.mNeedsPath)
        {
          temp += map_item.second.mPath;
        }
        
        // The return of c_str is null terminated and contiguous in C++11
        if( memcpy(_stored_argv[arg_num], temp.c_str(), strlen(temp.c_str())+1) == nullptr)
        {
          if(NOISY)
          {
            printf("### handcar_cosim::OptionsStorage::_loadArgMatrix(), call failed, unable to memcpy options text for option %s.\n", temp.c_str());
          }
          return ARGV_MEMORY_ERROR;
        }
        else
        {
          ++arg_num;
        }
      }
    }

    return SUCCESS;
  }


public:
  // The constructor that must be used when intending to use the set_simulator_parameter interface
  OptionsStorage():
    _flat_options(""),
    _stored_argv(nullptr),
    _stored_argc(0),
    _options_map{
      //The defaults for these values are set in initialize_simulator, not here. There entries are inert until as a result of a user command they are set to 'USED' for mIsUsed
      {"g", {UNUSED, 'g', "", UNUSED, UNUSED, 0, ""}}, // if present, enable pc histogram report
      {"l", {UNUSED, 'l', "", UNUSED, UNUSED, 0, ""}}, // if present, enable logging
      {"p", {UNUSED, 'p', "", NEEDS_VAL, UNUSED, 0, ""}},// Value argument determines number of processors
      {"m", {UNUSED, 'm', "", UNUSED, NEEDS_PATH, 0, ""}}, // Path argument is interpreted as a memory configuration 
      {"pc", {UNUSED, '0', "pc", NEEDS_VAL, UNUSED, 0, ""}}, // Value argument overrides the ELF entry point
      {"hartids", {UNUSED, '0', "hartids", UNUSED, NEEDS_PATH, 0, ""}}, // Path argument is used to explicitly set the hartids
      {"ic", {UNUSED, '0', "ic", UNUSED, NEEDS_PATH, 0, ""}}, // Path argument is used to configure the instruction cache model
      {"dc", {UNUSED, '0', "dc", UNUSED, NEEDS_PATH, 0, ""}}, // Path argument is used to configure the data cache model
      {"l2", {UNUSED, '0', "l2", UNUSED, NEEDS_PATH, 0, ""}}, // Path argument is used to configure the l2 cache model
      {"log-cache-miss", {UNUSED, '0', "log-cache-miss", UNUSED, UNUSED, 0, ""}}, // if present, enable logging of estimated cache misses
      {"varch", {UNUSED, '0', "varch", UNUSED, NEEDS_PATH, 0, ""}}, // Path argument is used to configure the RISC-V Vector uArch string
      //
      //WARNING, IT'S NOT A GREAT IDEA TO PLAY WITH THESE FOLLOWING OPTIONS UNLESS YOU KNOW WHAT YOU'RE DOING
      //
      {"isa", {UNUSED, '0', "isa", UNUSED, NEEDS_PATH, 0, ""}}, // Path argument is used to set the RISC-V ISA string
      {"d", {UNUSED, 'd', "", UNUSED, UNUSED, 0, ""}},// if present, enable debug human-interactive mode
      {"H", {UNUSED, 'h', "", UNUSED, UNUSED, 0, ""}}, // if present starts the simulator halted, meant to facilitate the connection of an external debugger
      //{"rbb-port", {UNUSED, '0', "rbb-port", NEEDS_VAL, UNUSED, 0, ""}}, // Value argument is interpreted as the port for Remote Bit Bang
      {"device", {UNUSED, '0', "device", UNUSED, NEEDS_PATH, 0, ""}}, // Path arguement is forwarded to device parser
//      {"extension", {UNUSED, '0', "extension", UNUSED, NEEDS_PATH, 0, ""}}, // Specify RoCC extension
      {"dump-dts", {UNUSED, '0', "dump-dts", UNUSED, UNUSED, 0, ""}}, // dump the device tree string and quit
      {"disable-dtb", {UNUSED, '0', "disable-dtb", UNUSED, UNUSED, 0, ""}}, // don't write the device tree blob into memory
      {"extlib", {UNUSED, '0', "extlib", UNUSED, NEEDS_PATH, 0, ""}}, // Shared library to load (Spike feature)
      {"dm-progsize", {UNUSED, '0', "dm-progsize", NEEDS_VAL, UNUSED, 0, ""}}, //"progsize" for the debug module
      {"dm-sba", {UNUSED, '0', "dm-sba", NEEDS_VAL, UNUSED, 0, ""}}, // Debug bus master supports up to <bits> wide accesses
      {"dm-auth", {UNUSED, '0', "dm-auth", UNUSED, UNUSED, 0, ""}}, // Debug module requires debugger to authenticate
      {"dmi-rti", {UNUSED, '0', "dmi-rti", NEEDS_VAL, UNUSED, 0, ""}}, // Number of run-test/idle cycles required for a dmi access
      {"dm-abstract-rti", {UNUSED, '0', "dmi-abstract-rti", NEEDS_VAL, UNUSED, 0, ""}}, // Number of run-test/idle cycles required for an abstract command to execute
      {"dm-no-hasel", {UNUSED, '0', "dm-no-hasel", UNUSED, UNUSED, 0, ""}}, // debug module supports hasel
      {"dm-no-abstract-csr", {UNUSED, '0', "dm-no-abstract-csr", UNUSED, UNUSED, 0, ""}}, // debug module wont support abstract to authenticate 
      {"dm-no-halt-groups", {UNUSED, '0', "dm-no-halt-groups", UNUSED, UNUSED, 0, ""}}, // debug module wont support halt groups 
      {"h", {UNUSED, 'h', "", UNUSED, UNUSED, 0, ""}} // display help and quit.
    },
    _token_vector()
  {
    _stored_argc = 2;
    _stored_argv = (char **)malloc(_stored_argc * sizeof(char*));
    _allocateDummyOptions();
  } 


  // One and done mode. Spike orignal code is in charge of options validation. Not meant to be used with set_simulator_parameter 
  OptionsStorage(const char* options):
    _flat_options((options == nullptr) ? "" : options),
    _stored_argv(nullptr),
    _stored_argc(0),
    _options_map{},
    _token_vector()
  {
    _unpackFlatOptions();

    if(NOISY)
    {
      for(auto token : _token_vector)
      {
        printf("token: %s\n", token.c_str());
      }
    }

    if(_token_vector.size() > 0)
    {
      // Allocate argv
      _stored_argc = _token_vector.size() + 2;
      _stored_argv = (char **)malloc(_stored_argc * sizeof(char*));
      _allocateDummyOptions();
  
      for(int arg_num = 1; arg_num < (_stored_argc-1); ++arg_num)
      {
        _stored_argv[arg_num] = (char*)malloc(ARGV_ELEMENT_BUFFER_SIZE * sizeof(char));  
        memcpy(_stored_argv[arg_num], _token_vector.at(arg_num - 1).c_str() , strlen(_token_vector.at(arg_num - 1).c_str())+1);
      }
    }
    else
    {
      _stored_argc = 2;
      _stored_argv = (char **)malloc(_stored_argc * sizeof(char*));
      _allocateDummyOptions();
    }
  } 


  ~OptionsStorage()
  {
    for(int arg_num = 0; arg_num < _stored_argc; ++arg_num)
    {
      free(_stored_argv[arg_num]);
      _stored_argv[arg_num] = nullptr;
    }

    free(_stored_argv);
    _stored_argv = nullptr;    
  }


  char** exposeStoredArgv()
  {
    return _stored_argv;
  }


  int exposeStoredArgc()
  {
    return _stored_argc;
  } 


  // These can't be methods of OptionsStorage, but they need access to OptionsStorage private that ought not be more widely exposed.
  friend void initialize_simulator(const char* options);
  friend int set_simulator_parameter(const char* name, const uint64_t* pValue, const char* path);

};
OptionsStorage* _pOptionsStorage;

bool isa_rv32;  // true if simulator configured (via isa cmdline option) as 32-bits (RV32)
bool isa_D;     // true if double-precision floating pt extension configured in

void initialize_simulator(const char* options)
{
  // Hopefully the user has called set_simulator_parameter a number of times before calling initialize_simulator, but handle the contingency if they didn't.
  if(_pOptionsStorage == nullptr)
  {
    if(options != nullptr)
    {
      _pOptionsStorage = new OptionsStorage(options);
    }
    else
    {
      _pOptionsStorage = new OptionsStorage();
    }
  }
  else // The user called set_simulator_parameter earlier
  {
    // Read the options map into a reallocated argv holder.
    int rcode = _pOptionsStorage->_resetArgMatrix();
    if(rcode != 0)
    {
      if(NOISY)
      {
        printf("### handcar_cosim::OptionsStorage::_resetArgMatrix. OptionsStorage error code: %d, Cannot proceed.\n", rcode);
      }
      terminate_simulator();
      return; // Leave early because options memory reallocation failed. 
      
    }
    rcode = _pOptionsStorage->_loadArgMatrix();
    if(rcode != 0)
    {
      if(NOISY)
      {
        printf("### handcar_cosim::OptionsStorage::_loadArgMatrix. OptionsStorage error code: %d, Cannot proceed.\n", rcode);
      }
      terminate_simulator();
      return; // Leave early because options setting failed.
    }
  }

  int argc = _pOptionsStorage->exposeStoredArgc();
  char ** argv = _pOptionsStorage->exposeStoredArgv();

  //Dump options
  if(NOISY)
  { 
    printf("Received additional options: ");
    for(int arg = 0; arg < argc; ++arg)
    {
     printf("%s, ", argv[arg]);
    }
    printf("\n");
  }
  
  bool debug = false;
  bool halted = false;
  bool histogram = false;
  bool log = false;
  bool socket = false;  // command line option -s
  bool dump_dts = false;
  bool dtb_enabled = true;
  bool real_time_clint = false;
  size_t nprocs = 1;
  const char* kernel = NULL;
  reg_t kernel_offset, kernel_size;
  const char* bootargs = NULL;
  reg_t start_pc = reg_t(-1);
  bool log_cache = false;
  bool auto_init_mem = false;
  const char* isa = DEFAULT_ISA;
  const char* priv = DEFAULT_PRIV;
  const char* varch = DEFAULT_VARCH;
  unsigned dmi_rti = 0;
  std::vector<int> hartids;
 
  auto const hartids_parser = [&](const char *s) {
    std::string const str(s);
    std::stringstream stream(str);
 
    int n;
    while (stream >> n)
    {
      hartids.push_back(n);
      if (stream.peek() == ',') stream.ignore();
    }
  };

  option_parser_t parser;
  parser.option('d', 0, 0, [&](const char* s){debug = true;});
  parser.option('g', 0, 0, [&](const char* s){histogram = true;});
  parser.option('l', 0, 0, [&](const char* s){log = true;});
  parser.option('p', 0, 1, [&](const char* s){nprocs = atoi(s);});
  // I wanted to use --halted, but for some reason that doesn't work.
  parser.option('H', 0, 0, [&](const char* s){halted = true;});
  parser.option(0, "pc", 1, [&](const char* s){start_pc = strtoull(s, 0, 0);});
  parser.option(0, "hartids", 1, hartids_parser);
  parser.option(0, "ic", 1, [&](const char* s){ic = new icache_sim_t(s);});
  parser.option(0, "dc", 1, [&](const char* s){dc = new dcache_sim_t(s);});
  parser.option(0, "l2", 1, [&](const char* s){l2 = cache_sim_t::construct(s, "L2$");});
  parser.option(0, "log-cache-miss", 0, [&](const char* s){log_cache = true;});
  parser.option(0, "auto-init-mem", 0, [&](const char* s){auto_init_mem = true;});
  parser.option(0, "isa", 1, [&](const char* s){isa = s;});
  parser.option(0, "priv", 1, [&](const char* s){priv = s;});
  parser.option(0, "varch", 1, [&](const char* s){varch = s;});
  //parser.option(0, "extension", 1, [&](const char* s){extensions.push_back(find_extension(s));});
  parser.option(0, "dump-dts", 0, [&](const char *s){dump_dts = true;});
  parser.option(0, "disable-dtb", 0, [&](const char *s){dtb_enabled = false;});
  parser.option(0, "kernel", 1, [&](const char* s){kernel = s;});
  parser.option(0, "bootargs", 1, [&](const char* s){bootargs = s;});
  parser.option(0, "real-time-clint", 0, [&](const char *s){real_time_clint = true;});
  parser.option(0, "extlib", 1, [&](const char *s){
    void *lib = dlopen(s, RTLD_NOW | RTLD_GLOBAL);
    if (lib == NULL) {
      fprintf(stderr, "Unable to load extlib '%s': %s\n", s, dlerror());
      exit(-1);
    }
  });
  FILE *cmd_file = NULL;
  parser.option(0, "debug-cmd", 1, [&](const char* s){
     if ((cmd_file = fopen(s, "r"))==NULL) {
        fprintf(stderr, "Unable to open command file '%s'\n", s);
        exit(-1);
     }
  });

  auto argv1 = parser.parse(argv);

  std::string isa_str = isa;
  isa_rv32 = isa_str.find("RV32") != std::string::npos;
  isa_D = (isa_str.find("F") != std::string::npos) && (isa_str.find("D") != std::string::npos);

  _pSimulatorTopLevel = new simlib_t(isa, priv, varch, nprocs, halted, bootargs, start_pc, hartids, auto_init_mem, cmd_file);
  _pSimulatorTopLevel->set_dtb_enabled(dtb_enabled);
 
  if (ic && l2) ic->set_miss_handler(&*l2);
  if (dc && l2) dc->set_miss_handler(&*l2);
  if (ic) ic->set_log(log_cache);
  if (dc) dc->set_log(log_cache);
  for (size_t i = 0; i < nprocs; i++)
  {
  if (ic) _pSimulatorTopLevel->get_core(i)->get_mmu()->register_memtracer(&*ic);
  if (dc) _pSimulatorTopLevel->get_core(i)->get_mmu()->register_memtracer(&*dc);
  }
 
  _pSimulatorTopLevel->set_log(log);
  _pSimulatorTopLevel->set_histogram(histogram);

  argc=0;
  argv=nullptr;
}


void terminate_simulator()
{
  // NOTE: the if guards around all the delete statements are needed because it is possible that some of these are not allocated when terminate_simulator is called, since it is an external API function.
  if(_pSimulatorTopLevel != nullptr)
  {
    delete _pSimulatorTopLevel;
    _pSimulatorTopLevel = nullptr;
  }

  if(_pOptionsStorage != nullptr)
  { 
    delete _pOptionsStorage;
    _pOptionsStorage = nullptr;
  }

  // originally handled by smart pointers, but we have to delete these manually now.
  if(ic != nullptr)
  {
    delete ic;
    ic = nullptr;
  }

  if(dc != nullptr)
  {
    delete dc;
    dc = nullptr;
  }

  if(l2 != nullptr)
  {
    delete l2;
    l2 = nullptr;
  }
}


void clearSimulatorLeaveOptions()
{
  if(_pSimulatorTopLevel != nullptr)
  {
    delete _pSimulatorTopLevel;
    _pSimulatorTopLevel = nullptr;
  }

  // originally handled by smart pointers, but we have to delete these manually now.
  if(ic != nullptr)
  {
    delete ic;
    ic = nullptr;
  }

  if(dc != nullptr)
  {
    delete dc;
    dc = nullptr;
  }

  if(l2 != nullptr)
  {
    delete l2;
    l2 = nullptr;
  }
}


int set_simulator_parameter(const char* name, const uint64_t* pValue, const char* path)
{
  if(_pOptionsStorage == nullptr)
  {
     _pOptionsStorage = new OptionsStorage();
  }

  // This call just modifies the options map so that the next time initialize_simulator is called, the simulator sees the intended options to load.
  int rcode = _pOptionsStorage->_rejectOrEnroll(name, pValue, path);

  // end early if something didn't work
  if(rcode != 0)
  {
    if(NOISY)
    {
      printf("### handcar_cosim::set_simulator_parameter(), call failed with error code: %d\n", rcode);
    }
    return rcode;
  }

  // Reinitialization has been seen not to work, so we will indicate to the user that this is not ok
  if(_pSimulatorTopLevel != nullptr){
    return 10;
  }

  return 0;
}


int simulator_load_elf(int target_id, const char* elf_path)
{
  int rcode = 1;
  if(_pSimulatorTopLevel != nullptr)
  {
     // checks only that a dummy entry has been made for the elf filepath to be stored. 
     rcode = _pSimulatorTopLevel->load_program_now(elf_path);
  }
  else 
  {
     if(NOISY)
     {
       printf("### handcar_cosim::simulator_load_elf(...), simulator not initialized before simulator_load_elf(...) called.\n");
     }
  }

  //dump_memory("./memdump.txt");

  return rcode;
}


void dump_memory(const char* file_to_create)
{
  //if(_pMemories != nullptr)
  //{
  //  // dump the dense memory model
  //  for(auto& mem: *_pMemories)
  //  {
  //    const size_t base_address = mem.first;
  //    const uint8_t* data = reinterpret_cast<uint8_t*>( mem.second->contents());
  //    const size_t total_size = mem.second->size();
  //    if(total_size % size_t(8))
  //    {
  //      printf("### handcar_cosim::dump_memory, size of memory region is not a multiple of 8 bytes!");
  //      return;
  //    }

  //    std::fstream dump(std::string(file_to_create), std::fstream::out);
  //    if(!dump)
  //    { 
  //      printf("### handcar_cosim::dump_memory, can't open memory dump file!");
  //      return;
  //    }

  //    for(size_t byte_idx = 0; byte_idx < total_size; byte_idx += size_t(8))
  //    {
  //      uint64_t chunk_buffer = ((uint64_t(data[byte_idx]) & 0xFF ) << 56ull) | ((uint64_t(data[byte_idx + 1]) & 0xFF) << 48ull) | ((uint64_t(data[byte_idx + 2]) & 0xFF) << 40ull) | ((uint64_t(data[byte_idx + 3]) & 0xFF) << 32ull) | ((uint64_t(data[byte_idx + 4]) & 0XFF) << 24ull) | ((uint64_t(data[byte_idx + 5]) & 0xFF) << 16ull) | ((uint64_t(data[byte_idx + 6]) & 0xFF) << 8ull) | uint64_t(data[byte_idx + 7]); 

  //      dump << std::hex << std::setfill('0') << std::setw(16) << byte_idx + base_address << ": " << std::setw(16) << chunk_buffer << std::endl;
  //    }
  //  }

    // Now dump the sparse memory model
     std::fstream dump2(std::string("./sparsedump.txt"), std::fstream::out);
    if(!dump2)
    { 
      printf("### handcar_cosim::dump_memory, can't open memory dump file!");
      return;
    }

    _pSimulatorTopLevel->dump_sparse_memory(dump2);    
  //}
}


int step_simulator(int target_id, int num_steps, int stx_failed)
{
  return _pSimulatorTopLevel->step_simulator(target_id, num_steps, stx_failed);
}


int get_disassembly(const uint64_t* pc, char** opcode, char** disassembly)
{
  return _pSimulatorTopLevel->get_disassembly(0, pc, opcode, disassembly);
}


int get_disassembly_for_target(int target_id, const uint64_t* pc, char** opcode, char** disassembly)
{
  return _pSimulatorTopLevel->get_disassembly(target_id, pc, opcode, disassembly);
}


int get_simulator_version(char* version)
{
  const char version_string[] = "0.0\0";
  if(version == nullptr)
  {
    return 1;
  }
  if(sizeof(version_string) > sizeof(version))
  {
    printf("#### handcar_cosim::get_simulator_version, not enough room in 'version' string buffer");
    return 1;
  }

  strcpy(version, version_string);   

  return 0;
}

//NEW DEBUG
int read_simulator_register(int target_id, const char* pRegName, uint8_t* pValue, int length)
{
  //Check that the pointers point to something
  if(pRegName == nullptr || pValue == nullptr || _pSimulatorTopLevel == nullptr)
  {
    return 1;
  }

  // Is the user asking to write to a register that actually exists? 
  int status = 0;
  uint8_t category = 0; // Four is not one of the admissible categories
  uint64_t index = _pSimulatorTopLevel->get_csr_number(std::string(pRegName));
  std::string temp_name = _pSimulatorTopLevel->get_csr_name(index);

  // Check if this is any of the other types of register
  if(temp_name.find("unknown") != std::string::npos)
  {
    category = 1;
    index = _pSimulatorTopLevel->get_xpr_number(std::string(pRegName));
    temp_name = _pSimulatorTopLevel->get_xpr_name(index);
  }

  if(temp_name.find("unknown") != std::string::npos)
  {
    category = 2;
    index = _pSimulatorTopLevel->get_fpr_number(std::string(pRegName));
    temp_name = _pSimulatorTopLevel->get_fpr_name(index);
  }

  if(temp_name.find("unknown") != std::string::npos)
  {
    category = 3;
    index = _pSimulatorTopLevel->get_vecr_number(std::string(pRegName));
    temp_name = _pSimulatorTopLevel->get_vecr_name(index);
  }

  if(temp_name.find("unknown") != std::string::npos)
  {
    category = 4; //fail category
    status = 3;
  }

  //PC is a special case since its not directly writeable in Spike code
  if(strcmp(pRegName, "PC") == 0 || strcmp(pRegName, "pc") == 0)
  {
    category = 5;
    status = 0;
  }

  //privilege is internal register to force, should bypass CSR/register and access state of proc
  if(strcmp(pRegName, "PRIVILEGE") == 0 || strcmp(pRegName, "privilege") == 0)
  {
    category = 6;
    status = 0;
  }

  // Check the category of the register and try to obtain the name
  uint32_t my_length = length;
  switch(category)
  {
    case(0) : //CSR
    {
      status = _pSimulatorTopLevel->read_csr(static_cast<uint64_t>(target_id), static_cast<uint64_t>(index), reinterpret_cast<uint64_t*>(pValue), &my_length);         
      break;
    }
    case(1) : //XPR
    {
      status = _pSimulatorTopLevel->read_xpr(static_cast<uint64_t>(target_id), static_cast<uint64_t>(index), reinterpret_cast<uint64_t*>(pValue), &my_length);         
      break;
    }
    case(2) : //FPR
    {
      status = _pSimulatorTopLevel->read_fpr(static_cast<uint64_t>(target_id), static_cast<uint64_t>(index), pValue, &my_length);         
      break;
    }
    case(3) : //VR
    {
      status = _pSimulatorTopLevel->read_vecr(static_cast<uint64_t>(target_id), static_cast<uint64_t>(index), pValue, &my_length);         
      break;
    }  
    case(5) : //PC
    {
      status = _pSimulatorTopLevel->get_pc_api(static_cast<int>(target_id), reinterpret_cast<uint8_t*>(pValue), std::string(pRegName), my_length) ? int(0) : int(3);     
      break;
    }
    case(6) : //privilege
    {
      status = _pSimulatorTopLevel->get_privilege_api(static_cast<uint64_t>(target_id), reinterpret_cast<uint64_t*>(pValue)) ? int(0) : int(3);
      break;
    }
    default:
      status = 3; // failure
  }

  return status;
}


int partial_read_large_register(int target_id, const char* pRegName, uint8_t* pValue, uint32_t length, uint32_t offset)
{
  //Check that the pointers point to something
  if(pRegName == nullptr || pValue == nullptr || _pSimulatorTopLevel == nullptr)
  {
    return 1;
  }

  // Is the user asking to write to a register that actually exists? 
  int status = 0;
  uint8_t category = 3; // Four is not one of the admissible categories
  uint64_t index = _pSimulatorTopLevel->get_vecr_number(std::string(pRegName));
  std::string temp_name = _pSimulatorTopLevel->get_vecr_name(index);

  // Check if this is any of the other types of register
  if(temp_name.find("unknown") != std::string::npos)
  {
    category = 4; //fail category
    status = 3;
  }

  // Check the category of the register and try to obtain the name
  switch(category)
  {
    case(3) : //VR
    {
      status = _pSimulatorTopLevel->partial_read_vecr(static_cast<uint64_t>(target_id), static_cast<uint64_t>(index), pValue, length, offset);         
      break;
    }  
    default:
      status = 3; // failure
  }

  return status;
}


int partial_write_large_register(int target_id, const char* pRegName, const uint8_t* pValue, uint32_t length, uint32_t offset)
{
  //Check that the pointers point to something
  if(pRegName == nullptr || pValue == nullptr || _pSimulatorTopLevel == nullptr)
  {
    return 1;
  }

  // Is the user asking to write to a register that actually exists? 
  int status = 0;
  uint8_t category = 3; // Four is not one of the admissible categories
  uint64_t index = _pSimulatorTopLevel->get_vecr_number(std::string(pRegName));
  std::string temp_name = _pSimulatorTopLevel->get_vecr_name(index);

  // Check if this is any of the other types of register
  if(temp_name.find("unknown") != std::string::npos)
  {
    category = 4; //fail category
    status = 3;
  }

  // Check the category of the register and try to obtain the name
  switch(category)
  {
    case(3) : //VR
    {
      status = _pSimulatorTopLevel->partial_write_vecr(static_cast<uint64_t>(target_id), static_cast<uint64_t>(index), pValue, length, offset);         
      break;
    }  
    default:
      status = 3; // failure
  }

  return status;
}


int write_simulator_register(int target_id, const char* pRegName, const uint8_t* data, int length)
{
  //Check that the pointers point to something
  if(pRegName == nullptr || data == nullptr || _pSimulatorTopLevel == nullptr)
  {
    return 1;
  }

  // Is the user asking to write to a register that actually exists? 
  int status = 0;
  uint8_t category = 0; // Four is not one of the admissible categories
  uint64_t index = _pSimulatorTopLevel->get_csr_number(std::string(pRegName));
  std::string temp_name = _pSimulatorTopLevel->get_csr_name(index);

  // Check if this is any of the other types of register
  if(temp_name.find("unknown") != std::string::npos)
  {
    category = 1;
    index = _pSimulatorTopLevel->get_xpr_number(std::string(pRegName));
    temp_name = _pSimulatorTopLevel->get_xpr_name(index);
  }

  if(temp_name.find("unknown") != std::string::npos)
  {
    category = 2;
    index = _pSimulatorTopLevel->get_fpr_number(std::string(pRegName));
    temp_name = _pSimulatorTopLevel->get_fpr_name(index);
  }

  if(temp_name.find("unknown") != std::string::npos)
  {
    category = 3;
    index = _pSimulatorTopLevel->get_vecr_number(std::string(pRegName));
    temp_name = _pSimulatorTopLevel->get_vecr_name(index);
  }

  if(temp_name.find("unknown") != std::string::npos)
  {
    category = 4; //fail category
    status = 3;
  }

  //PC is a special case since its not directly writeable in Spike code
  if(strcmp(pRegName, "PC") == 0 || strcmp(pRegName, "pc") == 0)
  {
    category = 5;
    status = 0;
  }

  //privilege is internal register to force, should bypass CSR/register and access state of proc
  if(strcmp(pRegName, "PRIVILEGE") == 0 || strcmp(pRegName, "privilege") == 0)
  {
    category = 6;
    status = 0;
  }

  // Check the category of the register and try to obtain the name
  uint32_t my_length = static_cast<uint32_t>(length);
  switch(category)
  {
    case(0) : //CSR
    {
      status = _pSimulatorTopLevel->write_csr(static_cast<uint64_t>(target_id), static_cast<uint64_t>(index), reinterpret_cast<const uint64_t*>(data), my_length);         
      break;
    }
    case(1) : //XPR
    {
      status = _pSimulatorTopLevel->write_xpr(static_cast<uint64_t>(target_id), static_cast<uint64_t>(index), reinterpret_cast<const uint64_t*>(data), my_length);         
      break;
    }
    case(2) : //FPR
    {
      status = _pSimulatorTopLevel->write_fpr(static_cast<uint64_t>(target_id), static_cast<uint64_t>(index), data, my_length);         
      break;
    }
    case(3) : //VR
    {
      status = _pSimulatorTopLevel->write_vecr(static_cast<uint64_t>(target_id), static_cast<uint64_t>(index), data, my_length);         
      break;
    }  
    case(5) : //PC
    {
      status = _pSimulatorTopLevel->set_pc_api(static_cast<int>(target_id), std::string(pRegName), reinterpret_cast<const uint8_t*>(data), my_length) ? int(0) : int(3);     
      break;
    }
    case(6) : //privilege
    {
      status = _pSimulatorTopLevel->set_privilege_api(static_cast<int>(target_id), reinterpret_cast<const uint64_t*>(data)) ? int(0) : int(3);
      break;
    }
    default:
      status = 3; // failure
  }

  return status;
}

int read_simulator_memory(int target_id, const uint64_t* addr, int length, uint8_t* data)
{ 
  // check that the pointers point to something 
  if(addr == nullptr || data == nullptr || _pSimulatorTopLevel == nullptr)
  {
    return 1;
  }

  // check that the length argument is not out of regulation
  if(length < 0 || length > 8)
  {
    return 2;
  }

  // the checks such as they are have passed, perform the read
  _pSimulatorTopLevel->sparse_read_partially_initialized(static_cast<reg_t>(*addr), static_cast<size_t>(length), data);

  return 0;
}

int write_simulator_memory(int target_id, const uint64_t* addr, int length, const uint8_t* data)
{ 
  // check that the pointers point to something 
  if(addr == nullptr || data == nullptr || _pSimulatorTopLevel == nullptr)
  {
    return 1;
  }

  // check that the length argument is not out of regulation
  if(length < 0)
  {
    return 2;
  }

  if(_pSimulatorTopLevel->sparse_is_pa_initialized(static_cast<reg_t>(*addr), static_cast<size_t>(length)))
  {
    _pSimulatorTopLevel->sparse_write(static_cast<reg_t>(*addr), data, static_cast<size_t>(length));
  }
  else
  {
    _pSimulatorTopLevel->initialize_multiword(static_cast<reg_t>(*addr), static_cast<size_t>(length), data);
  }

  return 0;
}

int initialize_simulator_memory(int target_id, const uint64_t* addr, int length, uint64_t data)
{ 
  // check that the pointers point to something 
  if(addr == nullptr || _pSimulatorTopLevel == nullptr)
  {
    return 1;
  }

  // check that the length argument is not out of regulation
  if(length < 0 || length > 8)
  {
    return 2;
  }

  // the checks such as they are have passed, perform the read
  _pSimulatorTopLevel->sparse_initialize_pa(static_cast<reg_t>(*addr), data, static_cast<size_t>(length));

  return 0;
}

int translate_virtual_address(int target_id, const uint64_t* vaddr, int intent, uint64_t* paddr, uint64_t* memattrs)
{
  if(vaddr == nullptr || paddr == nullptr || memattrs == nullptr || _pSimulatorTopLevel == nullptr)
    return 1;

  return _pSimulatorTopLevel->translate_virtual_address_api(target_id, vaddr, intent, paddr, memattrs);
}

bool is_gpr(std::string &rname) {
  uint64_t index = _pSimulatorTopLevel->get_xpr_number(rname);
  std::string temp_name = _pSimulatorTopLevel->get_xpr_name(index);

  return (temp_name.find("unknown") == std::string::npos);
}

int register_size(std::string &rname) {
  int length = isa_rv32 ? 4 : 8;  // set the 'default' register length based on the ISA (RV32 vs RV64)

  if (rname == std::string("PC")) {
    length = 8;  // if the register is the PC then set the length to 8...
  } else {
    uint64_t index = _pSimulatorTopLevel->get_fpr_number(rname);
    std::string temp_name = _pSimulatorTopLevel->get_fpr_name(index);

    if (temp_name == "unknown-fpr") {
      // not a floating pt register...
    } else {
      if ( isa_D )   // if double-precision floating pt extension present
        length = 8;  //   then floating pt registers are widened to 64 bits
    }
  }

  return length;
}

int read_simulator_register_fpix(uint32_t target_id, const char* registerName, uint64_t* pValue, uint64_t* mask)
{
  if(registerName == nullptr || pValue == nullptr || mask == nullptr || _pSimulatorTopLevel == nullptr)
  {
    return 1;
  }

  //const uint64_t buffer = (pValue & mask); // Are we masked on or masked off? Need to check what the convention of the bitmask is here.
  std::string nameForReference(registerName);

  int length = register_size(nameForReference);
  
  if(nameForReference != std::string("PC"))
  {
    // Is the user asking to read a register that actually exists? 
    int status = 0;
    uint8_t category = 0; // Four is not one of the admissible categories
    uint64_t index = _pSimulatorTopLevel->get_csr_number(nameForReference);
    std::string temp_name = _pSimulatorTopLevel->get_csr_name(index);

    // Check if this is any of the other types of register
    if(temp_name.find("unknown") != std::string::npos)
    {
      category = 1;
      index = _pSimulatorTopLevel->get_xpr_number(nameForReference);
      temp_name = _pSimulatorTopLevel->get_xpr_name(index);
    }

    if(temp_name.find("unknown") != std::string::npos)
    {
      category = 2;
      index = _pSimulatorTopLevel->get_fpr_number(std::string(nameForReference));
      temp_name = _pSimulatorTopLevel->get_fpr_name(index);
    }

    if(temp_name.find("unknown") != std::string::npos)
    {
      category = 4; //fail category
      status = 3;
    }
        
    // Check the category of the register and try to obtain the name
    uint32_t my_length = static_cast<uint32_t>(length);

    switch(category)
    {
      case(0) : //CSR
      {
        status = _pSimulatorTopLevel->read_csr(static_cast<uint32_t>(target_id), static_cast<uint64_t>(index), pValue, &my_length);         
        break;
      }
      case(1) : //XPR
      {
        status = _pSimulatorTopLevel->read_xpr(static_cast<uint32_t>(target_id), static_cast<uint64_t>(index), pValue, &my_length);         
        break;
      }
      case(2) : //FPR
      {
        uint8_t fp_buff[16] = {0};
        uint32_t fp_buff_size = sizeof(fp_buff);
        status = _pSimulatorTopLevel->read_fpr(static_cast<uint64_t>(target_id), static_cast<uint64_t>(index), fp_buff, &fp_buff_size);         
        memcpy(pValue, fp_buff, my_length);
        break;
      }
      // Fpix API is not suited for getting 128 bit values like from the vector registers and floating point registers yet.
      // load the data into an appropriate buffer and then copy the first 64 bits to the user's buffer 
      default:
        status = 3; // failure
    }

    *mask = 0xFFFFFFFFFFFFFFFFul; 

    return status;
  }
  else
  {
    int status = (_pSimulatorTopLevel->get_pc_api(static_cast<int>(target_id), reinterpret_cast<uint8_t*>(pValue), nameForReference, length) ? int(0) : int(3));     
  
    *mask = 0xFFFFFFFFFFFFFFFFul;
    return status;
  }
}


int write_simulator_register_fpix(uint32_t target_id, const char* registerName, uint64_t value, uint64_t mask)
{
  if(registerName == nullptr || _pSimulatorTopLevel == nullptr)
  {
    return 1;
  }

  std::string nameForReference(registerName);

  //int length = 8;
  int length = register_size(nameForReference);


  uint64_t rval = value;

  if ( is_gpr(nameForReference) && (length == 4) ) {
    if ( (rval & 0x80000000) != 0)
      rval |= 0xffffffff00000000ull;
  }
      
  const uint64_t buffer = rval;     // Are we masked on or masked off?
                                    // Need to check what the convention of the bitmask is here.
  

  //std::cout << "[write_simulator_register_fpix] " << nameForReference << " = !!!" << std::hex << rval << std::dec << "!!!" << std::endl;

  return write_simulator_register(static_cast<int>(target_id), registerName, reinterpret_cast<const uint8_t*>(&buffer), length);
}


