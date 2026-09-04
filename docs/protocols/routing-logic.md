# Routing logic

TM-01 and CS-01 publish findings to RG-01 and context to RU-01. RU-01 publishes jurisdiction context to RG-01. RG-01 is the only agent allowed to finalize a report. Critical sanctions and MNPI findings bypass normal batching and page the compliance queue immediately. Messages are correlated by `trace_id`; duplicate delivery is ignored after the first durable acknowledgement.
