template <typename AssociateT>
void blog::read_lines(const std::string& read_from, AssociateT& outc)
{
	boost::split(outc, read_from, boost::is_any_of("\n"));
}

template <typename AssociateT>
void blog::parse_163_comment_object(const std::string& objstr, AssociateT& results)
{
	typedef typename AssociateT::key_type key_type;
	typedef typename AssociateT::mapped_type mapped_type;
	typedef typename split_result_type::iterator iterator;

	split_result_type  result_pre;
	std::string objv = objstr;
	//std::string::size_type s = obj.find_first_of(':');

	//objv = obj.substr(s, obj.length());
	boost::trim_if(objv, boost::is_any_of("{}"));

	boost::split(result_pre, objv, boost::is_any_of(","));
	if (result_pre.size() > 0)
	{
		for (iterator it = result_pre.begin();
				it != result_pre.end();
				++it)
		{
			split_result_type result_final;
			boost::split(result_final, *it, boost::is_any_of(":"));
			
			// data format [blogId:reference:c0-e1.....]
			// to format [blogId, reference, c0-e1]
			if (result_final.size() == 3)
				results.insert(std::make_pair(result_final[0], result_final[2]));
		}
	}
}

template <typename AssociateT>
void blog::parse_163_comment(const std::string& cmt, AssociateT& results)
{
	// for type safe
	typedef typename AssociateT::key_type	 key_type;
	typedef typename AssociateT::mapped_type  mapped_type;
	typedef typename split_result_type::iterator iterator;

	// c0-e9=number:270139035
	split_result_type  lines;
	this->read_lines(cmt, lines);
	if (!lines.empty())
	{
		for (iterator it = lines.begin();
				it != lines.end();
				++it)
		{
			// get out {c0-e9=number:270139035}'s  lines and parse 
			split_result_type kvpair_1;
			boost::split(kvpair_1, *it, boost::is_any_of("="));
			if (kvpair_1.size() == 2) // always ensure this 
			{
				split_result_type kvpair_2;
				boost::split(kvpair_2, kvpair_1[1], boost::is_any_of(":"));
				if (kvpair_2.size() == 2)
				{
					switch (kvpair_2[0][0])
					{
						// the format: {c0-e9 , 270139035}
						case 's':
							{
								// thanks to g++, we use (int)(blog::anonymous_enum) syntax here to avoid the type error
								// implicit anonymous_enum type to int is not permitted in g++
								// this code works well in MSVC++ 2008
								results.insert(std::make_pair(kvpair_1[0], 
												std::make_pair((int)Key_String, kvpair_2[1])
												));
								break;
							}
						case 'n':
							{
								results.insert(std::make_pair(kvpair_1[0], 
												std::make_pair((int)Key_Int, kvpair_2[1])
												));
								break;
							}
						case 'b':
							{
								results.insert(std::make_pair(kvpair_1[0], 
												std::make_pair((int)Key_Bolean, kvpair_2[1])
												));
								break;
							}
#if 0
						case 'O':
							{
								results.insert(std::make_pair(kvpair_1[0], 
												std::make_pair((int)Key_Bolean, kvpair_2[1])
												));
							}
#endif
						default:
							break;
					}
				}
			}
		}
	}
}

template <typename AssociateT>
void blog::parse_internet_string(const std::string& buffer, AssociateT& results)
{
	typedef typename AssociateT::key_type	 key_type;
	typedef typename AssociateT::mapped_type  mapped_type;

	split_result_type kvpair_pred;
	
	typedef typename split_result_type::iterator sr_iterator;

	boost::split(kvpair_pred, buffer, boost::is_any_of("&"));
	if (!kvpair_pred.empty())
	{
		for (sr_iterator it = kvpair_pred.begin();
				it != kvpair_pred.end();
				++it)	
		{
			split_result_type  kvpair_result;
			boost::split(kvpair_result, *it, boost::is_any_of("="));
			if (kvpair_result.size() == 2)
				results.insert(std::make_pair(kvpair_result[0], kvpair_result[1]));
		}
	}
}

template <typename AssociateT>
void blog::parse_sina_comment(const std::string& cmt, AssociateT& results)
{
	this->parse_internet_string(cmt, results);
}

// the format is similar to sina, so we forward the call to <parse_sina_comment>
// but it may changes in the future
template <typename AssociateT>
void blog::parse_tianya_comment(const std::string& cmt, AssociateT& results)
{
	this->parse_internet_string(cmt, results);	
}
