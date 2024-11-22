<?php

namespace App\Http\Controllers\Auth;

use App\Models\User;
use App\Models\Tenant;
use Illuminate\View\View;
use Illuminate\Http\Request;
use Illuminate\Validation\Rules;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\RedirectResponse;
use Illuminate\Auth\Events\Registered;

class RegisteredUserController extends Controller
{
    /**
     * Display the registration view.
     */
    public function create(): View
    {
        return view('auth.register');
    }

    /**
     * Handle an incoming registration request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request): RedirectResponse
    {
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'lowercase', 'email', 'max:255', 'unique:' . User::class],
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
            'subdomain' => ['required', 'alpha', 'unique:domains,domain'],
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $tenant = Tenant::create([
            'name' => $request->name,
        ]);
        $tenant->createDomain($request->subdomain);
        $user->tenants()->attach($tenant->id);

        event(new Registered($user));

        Auth::login($user);

        return redirect('http://' . $request->subdomain . '.'. config('tenancy.central_domains')[0] . route('dashboard', absolute: false));
    }
}
