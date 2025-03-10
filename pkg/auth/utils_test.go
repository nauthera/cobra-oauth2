package auth

import "testing"

func Test_joinScopes(t *testing.T) {
	type args struct {
		scopes []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "single scope",
			args: args{scopes: []string{"read"}},
			want: "read",
		},
		{
			name: "multiple scopes",
			args: args{scopes: []string{"read", "write"}},
			want: "read write",
		},
		{
			name: "no scopes",
			args: args{scopes: []string{}},
			want: "",
		},
		{
			name: "scopes with spaces",
			args: args{scopes: []string{"read", "write", "delete"}},
			want: "read write delete",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := joinScopes(tt.args.scopes); got != tt.want {
				t.Errorf("joinScopes() = %v, want %v", got, tt.want)
			}
		})
	}
}
